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
public class BrokerKeyStoreTest {
    @TempDir
    Path rootDir;

    private BrokerKeyStore brokerKeyStore;

    @BeforeEach
    public void setup() {
        brokerKeyStore = new BrokerKeyStore(rootDir);
    }

    @Test
    void GIVEN_BrokerKeyStore_WHEN_getKeyStore_THEN_encryptedJksCreated() {
        Assertions.assertNotEquals("", brokerKeyStore.getJksPassword(),
            "keystore password should not be empty");
        Assertions.assertEquals(rootDir.resolve("keystore.jks").toString(), brokerKeyStore.getJksPath(),
            "keystore should be created in the root dir");
    }

    // TODO: increase test coverage!
}
