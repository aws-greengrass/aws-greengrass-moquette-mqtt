/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttclient;

import com.aws.greengrass.certificatemanager.CertificateManager;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.mqtt.MQTTService;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.testcommons.testutilities.GGServiceTestUtil;
import io.moquette.BrokerConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.ConnectException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class MQTTServiceTest extends GGServiceTestUtil {
    private static final long TEST_TIME_OUT_SEC = 30L;

    @TempDir
    Path rootDir;

    private Kernel kernel;

    @Mock
    CertificateManager mockCertificateManager;

    @BeforeEach
    void setup() {
        kernel = new Kernel();
        kernel.getContext().put(CertificateManager.class, mockCertificateManager);
    }

    @AfterEach
    void cleanup() {
        kernel.shutdown();
    }

    @Test
    void GIVEN_Greengrass_with_broker_WHEN_start_nucleus_THEN_broker_starts_on_port_8883()
        throws InterruptedException, IOException {
        CountDownLatch serviceRunning = new CountDownLatch(1);
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
            getClass().getResource("config.yaml").toString());
        kernel.getContext().addGlobalStateChangeListener((GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(MQTTService.SERVICE_NAME) && service.getState().equals(State.RUNNING)) {
                serviceRunning.countDown();
            }
        });
        kernel.launch();
        assertTrue(serviceRunning.await(TEST_TIME_OUT_SEC, TimeUnit.SECONDS));

        // Connect to port 8883 just to confirm server is listening on port
        Socket socket = new Socket("localhost", 8883);
        socket.close();
    }

    @Test
    void GIVEN_Greengrass_with_broker_WHEN_start_nucleus_THEN_broker_doesnt_start_on_plain_tcp_port()
        throws InterruptedException {
        CountDownLatch serviceRunning = new CountDownLatch(1);
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
            getClass().getResource("config.yaml").toString());
        kernel.getContext().addGlobalStateChangeListener((GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(MQTTService.SERVICE_NAME) && service.getState().equals(State.RUNNING)) {
                serviceRunning.countDown();
            }
        });
        kernel.launch();
        assertTrue(serviceRunning.await(TEST_TIME_OUT_SEC, TimeUnit.SECONDS));

        assertThrows(ConnectException.class, () -> {
            new Socket("localhost", BrokerConstants.PORT);
        });
    }
}
