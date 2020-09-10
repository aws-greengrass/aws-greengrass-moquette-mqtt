/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.iot.evergreen.mqtt.broker;

import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

@ExtendWith({MockitoExtension.class, EGExtension.class})
public class MQTTBrokerKeyStoreTest {

    // TODO: verify path
    private static final String path = "work/aws.greengrass.mqtt/serverstore.jks";
    private MQTTBrokerKeyStore mqttBrokerKeyStore;

    @BeforeEach
    public void setup() {
        mqttBrokerKeyStore = new MQTTBrokerKeyStore();
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getKeyStore_called_THEN_basic_keystore_generated()
        throws Exception {

        KeyStore brokerKeyStore = mqttBrokerKeyStore.getKeyStore();
        assertThat(brokerKeyStore.size(), is(0));
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getBrokerKeyStorePath_called_THEN_returns_valid_path() {

        String brokerKeyStorePath = mqttBrokerKeyStore.getBrokerKeyStorePath();
        assertThat(brokerKeyStorePath, equalTo(path));
    }

    // TODO: Add tests to verify write path
}
