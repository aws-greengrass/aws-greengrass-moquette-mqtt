/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.iot.evergreen.mqtt.broker;

import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith({MockitoExtension.class, EGExtension.class})
public class MQTTBrokerKeyStoreTest {

    @TempDir
    Path rootDir;

    private MQTTBrokerKeyStore mqttBrokerKeyStore;

    @BeforeEach
    public void setup() {
        mqttBrokerKeyStore = new MQTTBrokerKeyStore(rootDir);
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getKeyStore_called_THEN_basic_keystore_generated()
        throws Exception {
        //Assertions.assertEquals(mqttBrokerKeyStore.getKeyStorePassword(), "");
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getBrokerKeyStorePath_called_THEN_returns_valid_path() {

        //String brokerKeyStorePath = mqttBrokerKeyStore.getBrokerKeyStorePath();
        //assertThat(brokerKeyStorePath, equalTo(path));
    }

    // TODO: Add tests to verify write path
}
