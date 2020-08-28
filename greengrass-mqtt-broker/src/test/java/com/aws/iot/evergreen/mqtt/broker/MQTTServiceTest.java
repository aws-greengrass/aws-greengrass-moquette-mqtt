/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */

package com.aws.iot.evergreen.mqtt.broker;

import com.aws.iot.evergreen.dependency.State;
import com.aws.iot.evergreen.kernel.EvergreenService;
import com.aws.iot.evergreen.kernel.Kernel;
import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import com.aws.iot.evergreen.testcommons.testutilities.EGServiceTestUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith({MockitoExtension.class, EGExtension.class})
public class MQTTServiceTest extends EGServiceTestUtil {
    private static final long TEST_TIME_OUT_SEC = 30L;

    @TempDir
    Path rootDir;

    private Kernel kernel;

    @BeforeEach
    void setup() {
        kernel = new Kernel();
    }

    @AfterEach
    void cleanup() {
        kernel.shutdown();
    }

    @Test
    void GIVEN_Evergreen_with_broker_WHEN_start_kernel_THEN_broker_starts_on_port_8883()
        throws InterruptedException, IOException {
        CountDownLatch serviceRunning = new CountDownLatch(1);
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
            getClass().getResource("config.yaml").toString());
        kernel.getContext().addGlobalStateChangeListener((EvergreenService service, State was, State newState) -> {
            if (service.getName().equals(MQTTService.SERVICE_NAME) && service.getState()
                .equals(State.RUNNING)) {
                serviceRunning.countDown();
            }
        });
        kernel.launch();
        assertTrue(serviceRunning.await(TEST_TIME_OUT_SEC, TimeUnit.SECONDS));

        // Connect to port 8883 just to confirm server is listening on port
        Socket socket = new Socket("localhost", 8883);
        socket.close();
    }
}
