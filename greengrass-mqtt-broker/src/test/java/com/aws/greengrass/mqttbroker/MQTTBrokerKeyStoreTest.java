/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class MQTTBrokerKeyStoreTest {
    @TempDir
    Path rootDir;

    private MQTTBrokerKeyStore mqttBrokerKeyStore;

    @BeforeEach
    public void setup() {
        mqttBrokerKeyStore = new MQTTBrokerKeyStore(rootDir);
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getKeyStore_called_THEN_basic_keystore_generated() {
        Assertions.assertNotEquals("", mqttBrokerKeyStore.getJksPassword(),
            "keystore password should not be empty");
        Assertions.assertEquals(rootDir.resolve("keystore.jks").toString(), mqttBrokerKeyStore.getJksPath(),
            "keystore should be created in the root dir");
    }

    // TODO: increase test coverage!
}
