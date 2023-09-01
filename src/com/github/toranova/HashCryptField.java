/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.toranova;

import java.util.Map;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.apache.camel.InvalidPayloadException;
import org.apache.camel.Processor;

public class HashCryptField implements Processor {

    private AWSKMSHashcryptor m = null;
    private String[] mFields = null;

    public HashCryptField(){
    }

    public HashCryptField(String fields, String accessKey, String secretKey, String keyId, String hashAlgo, String hashSalt, int rotationPeriod) throws Exception {
        //System.out.printf("FIELDS: %s\n", fields);
        mFields = fields.split(" *, *");
        m = new AWSKMSHashcryptor(accessKey, secretKey, keyId, hashAlgo, hashSalt, rotationPeriod);
    }

    public HashCryptField(String fields, String keyId, String hashAlgo, String hashSalt, int rotationPeriod) throws Exception {
        //System.out.printf("FIELDS: %s\n", fields);
        mFields = fields.split(" *, *");
        m = new AWSKMSHashcryptor(keyId, hashAlgo, hashSalt, rotationPeriod);
    }

    public String testDecryptUTF8(String testcipher) throws Exception {
        return m.doDecryptUTF8(testcipher);
    }

    public void process(Exchange ex) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNodeBody = ex.getMessage().getBody(JsonNode.class);

        if (jsonNodeBody == null) {
            throw new InvalidPayloadException(ex, JsonNode.class);
        }

        Map<Object, Object> body = mapper.convertValue(jsonNodeBody, new TypeReference<Map<Object, Object>>(){});

        for (String s : mFields) {
            //System.out.printf("PROCESSING: %s\n", s);
            // for every field
            Object v = body.get(s);
            if (v == null) {
                continue;
            }

            if (v instanceof java.lang.String) {
                String _v = ((String) v).trim(); // trim whitespace
                String e = m.doEncryptUTF8(_v);

                // add encrypted field
                body.put(String.format("%s_enc", s), e);

                String h = m.doHash(_v);
                if (h instanceof java.lang.String) {
                    // overwrite value with hash
                    body.put(s, h);
                }
            }
        }

        // add the decryption context
        body.put("aws_enc_ctx", m.getDecryptionContext());
        ex.getMessage().setBody(body);
    }
}
