/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.dependency.State;
import com.aws.greengrass.device.ClientDevicesAuthServiceApi;
import com.aws.greengrass.device.api.GetCertificateRequest;
import com.aws.greengrass.device.exception.CertificateGenerationException;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.lifecyclemanager.exceptions.ServiceLoadException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.testcommons.testutilities.GGServiceTestUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class MQTTServiceTest extends GGServiceTestUtil {
    private static final long TEST_TIME_OUT_SEC = 30L;

    @TempDir
    Path rootDir;

    private Kernel kernel;

    @Mock
    ClientDevicesAuthServiceApi mockCDAServiceApi;

    @BeforeEach
    void setup() {
        // Set this property for kernel to scan its own classpath to find plugins
        System.setProperty("aws.greengrass.scanSelfClasspath", "true");

        kernel = new Kernel();
        kernel.getContext().put(ClientDevicesAuthServiceApi.class, mockCDAServiceApi);
    }

    @AfterEach
    void cleanup() {
        kernel.shutdown();
    }

    void startNucleusWithConfig(String config) throws InterruptedException {
        CountDownLatch serviceRunning = new CountDownLatch(1);
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i", getClass().getResource(config).toString());
        kernel.getContext().addGlobalStateChangeListener((GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(MQTTService.SERVICE_NAME) && service.getState().equals(State.RUNNING)) {
                serviceRunning.countDown();
            }
        });
        kernel.launch();
        assertTrue(serviceRunning.await(TEST_TIME_OUT_SEC, TimeUnit.SECONDS));
    }

    boolean isListeningOnPort(int port) {
        try (Socket socket = new Socket("localhost", port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @Test
    void GIVEN_defaultConfig_WHEN_startComponent_THEN_brokerStartsOnPort8883_and_subscriptions_dont_duplicate()
        throws InterruptedException, ServiceLoadException, CertificateGenerationException {
        startNucleusWithConfig("config.yaml");
        ArgumentCaptor<GetCertificateRequest> captor = ArgumentCaptor.forClass(GetCertificateRequest.class);
        Mockito.doNothing().when(mockCDAServiceApi).subscribeToCertificateUpdates(any());
        verify(mockCDAServiceApi, timeout(5_000).times(1)).subscribeToCertificateUpdates(captor.capture());
        kernel.locate(MQTTService.SERVICE_NAME).requestRestart();
        verify(mockCDAServiceApi, timeout(5_000).times(2)).subscribeToCertificateUpdates(any());
        kernel.locate(MQTTService.SERVICE_NAME).requestRestart();
        verify(mockCDAServiceApi, timeout(5_000).times(3)).subscribeToCertificateUpdates(any());
        kernel.locate(MQTTService.SERVICE_NAME).requestRestart();
        verify(mockCDAServiceApi, timeout(5_000).times(4)).subscribeToCertificateUpdates(any());
        Thread.sleep(1_000);

        assertThat(isListeningOnPort(8883), is(true));
        assertThat(isListeningOnPort(1883), is(false));
        // Validate that subscription requests are de-duplicateable because they are all exactly equal
        assertThat(captor.getAllValues().stream().distinct().count(), equalTo(1L));
    }

    @Test
    void GIVEN_nonDefaultPort_WHEN_startComponent_THEN_brokerStartsOnConfiguredPort() throws InterruptedException {
        startNucleusWithConfig("nonDefaultPort.yaml");

        assertThat(isListeningOnPort(9000), is(true));
        assertThat(isListeningOnPort(8883), is(false));
        assertThat(isListeningOnPort(1883), is(false));
    }
}
