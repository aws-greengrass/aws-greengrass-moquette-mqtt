/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.iot.evergreen.mqtt.broker;

import com.aws.iot.evergreen.kernel.Kernel;
import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, EGExtension.class})
public class MQTTBrokerKeyStoreTest {

    @TempDir
    Path rootDir;

    // TODO: verify path
    private static final String path = "work/aws.greengrass.mqtt/serverstore.jks";
    private MQTTBrokerKeyStore mqttBrokerKeyStore;
    @Mock
    private Kernel mockKernel;


    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getBrokerKeyStorePath_called_THEN_returns_valid_path() throws Exception {
        when(mockKernel.getWorkPath()).thenReturn(Paths.get("work"));
        mqttBrokerKeyStore = new MQTTBrokerKeyStore(mockKernel.getWorkPath());
        String brokerKeyStorePath = mqttBrokerKeyStore.getKeyStorePath();
        assertThat(brokerKeyStorePath, equalTo(path));
    }

    // TODO: Add tests to verify write path
}
