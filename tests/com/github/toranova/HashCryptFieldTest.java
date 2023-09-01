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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.DefaultExchange;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public final class HashCryptFieldTest {

    private DefaultCamelContext camelContext;

    private final ObjectMapper mapper = new ObjectMapper();

    private HashCryptField processor;

    private final String baseJson = "{" +
                "\"name\":\"Sum Ting Wong\"," +
                "\"nric\":\"1234567891 \"," +
                "\"long_code\":\"abascaakwjbawkdjabwkdjabwkdjbawkdjbawkjdbawkdjabwdkajwdbkawjbdakwjdbakwjdbawkjdbawkjdbawkdjabwkdajwbd___________awkdjabwddddddddddddddddddddddddddddawdawd12301923102931029dj1092dj1029jd\"" +
            "}";

    @Before
    public void setup() {
        camelContext = new DefaultCamelContext();
    }

    @Test
    public void shouldEncryptAndHash() throws Exception {
        Exchange exchange = new DefaultExchange(camelContext);

        exchange.getMessage().setBody(mapper.readTree(baseJson));

        processor = new HashCryptField("name, nric, long_code, donexist", "59d9d135-21ee-48d0-9322-d7243983f246", "SHA-256", "salt123", 5);
        processor.process(exchange);

        System.out.println(exchange.getMessage().getBody(String.class));
        JsonNode res = exchange.getMessage().getBody(JsonNode.class);
        assertEquals("405d29f0dcea8f1c01e45c8cb5d431ef8308697b115f9a1d061244c27b5fdc1a",
                ((ObjectNode) res).get("nric").textValue());
        assertEquals("24a5827a551ee3ef32daaa6cb806209204d552fed00f5ee27ea40110ee272a1b",((ObjectNode) res).get("name").textValue());

        String recover = processor.testDecryptUTF8(((ObjectNode) res).get("nric_enc").textValue());
        assertEquals("1234567891", recover);
        recover = processor.testDecryptUTF8(((ObjectNode) res).get("name_enc").textValue());
        assertEquals("Sum Ting Wong", recover);
    }

    @Test
    public void massEncryption() throws Exception {
        Exchange exchange;
        String recover;
        JsonNode res;

        processor = new HashCryptField("name, nric, long_code, abc", "59d9d135-21ee-48d0-9322-d7243983f246", "SHA-256", "salt123", 10000);
        for (int i = 0; i < 1000; i++) {
            exchange = new DefaultExchange(camelContext);
            exchange.getMessage().setBody(mapper.readTree(baseJson));
            processor.process(exchange);
            res = exchange.getMessage().getBody(JsonNode.class);
            assertEquals("405d29f0dcea8f1c01e45c8cb5d431ef8308697b115f9a1d061244c27b5fdc1a", ((ObjectNode) res).get("nric").textValue());
            assertEquals("24a5827a551ee3ef32daaa6cb806209204d552fed00f5ee27ea40110ee272a1b",((ObjectNode) res).get("name").textValue());
            recover = processor.testDecryptUTF8(((ObjectNode) res).get("nric_enc").textValue());
            assertEquals("1234567891", recover);
            recover = processor.testDecryptUTF8(((ObjectNode) res).get("name_enc").textValue());
            assertEquals("Sum Ting Wong", recover);
        }
    }

    @Test
    public void shouldRotateKeys() throws Exception {
        Exchange exchange;
        JsonNode res;
        String keyCtx1, keyCtx2, keyCtx3;

        exchange = new DefaultExchange(camelContext);
        exchange.getMessage().setBody(mapper.readTree(baseJson));

        processor = new HashCryptField("name, nric", "59d9d135-21ee-48d0-9322-d7243983f246", "SHA-256", "salt123", 3);
        processor.process(exchange);
        res = exchange.getMessage().getBody(JsonNode.class);
        keyCtx1 = ((ObjectNode) res).get("aws_enc_ctx").textValue();

        exchange = new DefaultExchange(camelContext);
        exchange.getMessage().setBody(mapper.readTree(baseJson));
        processor.process(exchange);

        exchange = new DefaultExchange(camelContext);
        exchange.getMessage().setBody(mapper.readTree(baseJson));
        processor.process(exchange);
        res = exchange.getMessage().getBody(JsonNode.class);
        keyCtx2 = ((ObjectNode) res).get("aws_enc_ctx").textValue();

        // third message still uses old keyCtx
        assertEquals(keyCtx1, keyCtx2);

        exchange = new DefaultExchange(camelContext);
        exchange.getMessage().setBody(mapper.readTree(baseJson));
        processor.process(exchange);
        res = exchange.getMessage().getBody(JsonNode.class);
        keyCtx3 = ((ObjectNode) res).get("aws_enc_ctx").textValue();

        // fourth message uses a different key ctx
        assertNotEquals(keyCtx1, keyCtx3);
    }
}
