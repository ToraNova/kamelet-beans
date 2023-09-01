package com.github.toranova;

import java.util.Base64;
import java.util.Arrays;
import java.security.SecureRandom;
import java.io.UnsupportedEncodingException;
import java.net.URI;

import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ProxyConfiguration;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMSIVBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.InvalidCipherTextException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AWSKMSHashcryptor {

    private String mProxy;
    private String mAwsAccessKey;
    private String mAwsSecretKey;
    private byte[] mHashSalt;
    private MessageDigest mHashAlgo;
    private String mKeyId;
    private KeyParameter mKeyParam;
    private String mKeyCtB64;
    private static int mNonceLen = 16;
    private int mRotationCount = 0;
    private int mRotationPeriod = 1000000;


    public AWSKMSHashcryptor(byte[] hardCodedKey) throws NoSuchAlgorithmException {
        // FOR DEBUGGING ONLY, DO NOT USE!
        mKeyParam = new KeyParameter(hardCodedKey);
        mKeyCtB64 = Base64.getEncoder().encodeToString(hardCodedKey);
        mKeyId = "00000000-0000-0000-0000-000000000000";
        mRotationPeriod = 5;
        initHashDigest("SHA-256", "salt123");
    }

    public AWSKMSHashcryptor(
            String kmsKeyId,
            String hashAlgo,
            String hashSalt,
            int rotationPeriod
    ) throws NoSuchAlgorithmException {
        // Initialize the KMS client
        mRotationPeriod = rotationPeriod;
        mKeyId = kmsKeyId;
        mAwsSecretKey = null;
        mAwsAccessKey = null;
        mProxy = null;

        initKeys();
        initHashDigest(hashAlgo, hashSalt);
    }

    public AWSKMSHashcryptor(
            String awsKeyId,
            String awsKeySecret,
            String kmsKeyId,
            String hashAlgo,
            String hashSalt,
            int rotationPeriod
    ) throws NoSuchAlgorithmException {
        mRotationPeriod = rotationPeriod;
        mKeyId = kmsKeyId;
        mAwsAccessKey = awsKeyId;
        mAwsSecretKey = awsKeySecret;
        mProxy = null;

        initKeys();
        initHashDigest(hashAlgo, hashSalt);
    }

    public AWSKMSHashcryptor(
            String awsKeyId,
            String awsKeySecret,
            String kmsKeyId,
            String hashAlgo,
            String hashSalt,
            int rotationPeriod,
            String proxy
    ) throws NoSuchAlgorithmException {
        mRotationPeriod = rotationPeriod;
        mKeyId = kmsKeyId;
        mAwsAccessKey = awsKeyId;
        mAwsSecretKey = awsKeySecret;
        mProxy = proxy;

        initKeys();
        initHashDigest(hashAlgo, hashSalt);
    }

    private void initKeys() throws NoSuchAlgorithmException {
        KmsClient client;

        if (mAwsAccessKey != null && mAwsSecretKey != null) {
            AwsBasicCredentials creds = AwsBasicCredentials.create(
                    mAwsAccessKey, mAwsSecretKey
            );

            if (mProxy != null) {
                SdkHttpClient httpClient = ApacheHttpClient.builder()
                    .proxyConfiguration(ProxyConfiguration.builder()
                        .endpoint(URI.create(mProxy))
                        .build())
                    .build();

                // Initialize the KMS client
                client = KmsClient.builder()
                    .httpClient(httpClient)
                    .credentialsProvider(StaticCredentialsProvider.create(creds))
                    .region(Region.AP_SOUTHEAST_1)
                    .build();

            } else {
                // Initialize the KMS client
                client = KmsClient.builder()
                    .credentialsProvider(StaticCredentialsProvider.create(creds))
                    .region(Region.AP_SOUTHEAST_1)
                    .build();
            }
        } else {
            client = KmsClient.builder()
                .region(Region.AP_SOUTHEAST_1)
                .build();
        }

        // Define the GenerateDataKey request
        GenerateDataKeyRequest request = GenerateDataKeyRequest.builder()
            .keyId(mKeyId)
            .keySpec("AES_128")
            .build();

        // Call kms:GenerateDataKey
        GenerateDataKeyResponse response = client.generateDataKey(request);
        byte[] keyPt = response.plaintext().asByteArray();
        mKeyParam = new KeyParameter(keyPt);

        byte[] keyCt = response.ciphertextBlob().asByteArray();
        mKeyCtB64 = Base64.getEncoder().encodeToString(keyCt);

        mRotationCount = 0;

        client.close();
    }

    public String getDecryptionContext(){
        return String.format("%s:%s", mKeyCtB64, mKeyId);
    }

    public String doEncryptUTF8(
            String plaintext
    ) throws
        java.io.UnsupportedEncodingException,
        InvalidCipherTextException,
        NoSuchAlgorithmException
    {
        return doEncrypt(plaintext.getBytes("UTF-8"));
    }

    public String doEncrypt(byte[] plaintext) throws InvalidCipherTextException, NoSuchAlgorithmException {

        // in and out
        if (mRotationCount >= mRotationPeriod) {
            // get new keys
            initKeys();
        }

        byte[] nonce = new byte[mNonceLen];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(nonce);

        PaddedBufferedBlockCipher cip = initCipher(true, nonce);
        byte[] buf = new byte[cip.getOutputSize(plaintext.length) + mNonceLen];
        int plen = cip.processBytes(plaintext, 0, plaintext.length, buf, mNonceLen);
        cip.doFinal(buf, mNonceLen + plen);
        System.arraycopy(nonce, 0, buf, 0, mNonceLen);

        mRotationCount += 1; // in and out
        return Base64.getEncoder().encodeToString(buf);
    }

    public String doDecryptUTF8(String ciphertext) throws InvalidCipherTextException {
        return doDecryptUTF8(Base64.getDecoder().decode(ciphertext));
    }

    public String doDecryptUTF8(byte[] ciphertext) throws InvalidCipherTextException {
        byte[] nonce = Arrays.copyOf(ciphertext, mNonceLen);
        PaddedBufferedBlockCipher cip = initCipher(false, nonce);

        byte[] buf = new byte[cip.getOutputSize(ciphertext.length - mNonceLen)];
        cip.processBytes(ciphertext, mNonceLen, ciphertext.length - mNonceLen, null, 0);
        cip.doFinal(buf, 0);
        return new String(terminateAtNullByte(buf));
    }

    public void initHashDigest(String algo, String salt) throws NoSuchAlgorithmException {
        if (algo.equals("SHA-256") || algo.equals("SHA-512")) {
            mHashAlgo = MessageDigest.getInstance(algo);
            mHashSalt = salt.getBytes();
        } else if (algo.equals("dropField") || algo.equals("drop")) {
            mHashAlgo = null;
            mHashSalt = null;
        } else {
            throw new NoSuchAlgorithmException(algo);
        }
    }

    private PaddedBufferedBlockCipher initCipher(boolean enc, byte[] nonce){
        // jason.chia
        // using CTR mode due to simplicity
        // we don't need fancy GCMs here since auth/int is not a requirement
        CBCBlockCipher cbc = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cip = new PaddedBufferedBlockCipher(cbc, new PKCS7Padding());
        cip.init(enc, new ParametersWithIV(mKeyParam, nonce));
        return cip;
    }

    public static byte[] terminateAtNullByte(byte[] buffer) {
        int nullPos = -1;
        for (int i = 0; i < buffer.length; i++) {
            if (buffer[i] == 0) {
                nullPos = i;
                break;
            }
        }

        if (nullPos != -1) {
            return Arrays.copyOf(buffer, nullPos);
        }
        return buffer;
    }

    public String doHash(String inp) {
        if (mHashAlgo != null && mHashSalt != null) {
            // reset the hash buffer
            mHashAlgo.reset();
            // prepend hashing salt
            mHashAlgo.update(mHashSalt);
            return bytesToHex(mHashAlgo.digest(inp.getBytes()));
        }

        return null;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hashString = new StringBuilder();
        for (byte b : bytes) {
            hashString.append(String.format("%02x", b));
        }
        return hashString.toString();
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
                    .digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
