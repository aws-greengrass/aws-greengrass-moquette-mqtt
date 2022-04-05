/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.certificatemanager.CertificateManager;
import com.aws.greengrass.certificatemanager.certificate.CsrProcessingException;
import com.aws.greengrass.dependency.State;
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
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

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
        throws InterruptedException, ServiceLoadException, CsrProcessingException, KeyStoreException {
        startNucleusWithConfig("config.yaml");
        ArgumentCaptor<Consumer<X509Certificate>> captor = ArgumentCaptor.forClass(Consumer.class);
        Mockito.doNothing().when(mockCertificateManager).subscribeToServerCertificateUpdates(anyString(), captor.capture());
        verify(mockCertificateManager, timeout(5_000).times(1)).subscribeToServerCertificateUpdates(any(), any());
        kernel.locate(MQTTService.SERVICE_NAME).requestRestart();
        verify(mockCertificateManager, timeout(5_000).times(2)).subscribeToServerCertificateUpdates(any(), any());
        kernel.locate(MQTTService.SERVICE_NAME).requestRestart();
        verify(mockCertificateManager, timeout(5_000).times(3)).subscribeToServerCertificateUpdates(any(), any());
        kernel.locate(MQTTService.SERVICE_NAME).requestRestart();
        verify(mockCertificateManager, timeout(5_000).times(4)).subscribeToServerCertificateUpdates(any(), any());
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
