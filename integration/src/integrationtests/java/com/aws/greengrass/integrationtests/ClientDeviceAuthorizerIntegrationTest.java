/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.integrationtests;

import com.aws.greengrass.clientdevices.auth.api.ClientDevicesAuthServiceApi;
import com.aws.greengrass.clientdevices.auth.certificate.CertificateHelper;
import com.aws.greengrass.clientdevices.auth.iot.Certificate;
import com.aws.greengrass.clientdevices.auth.iot.IotAuthClient;
import com.aws.greengrass.clientdevices.auth.iot.Thing;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.integrationtests.helpers.CertificateTestHelpersMoquette;
import com.aws.greengrass.lifecyclemanager.GlobalStateChangeListener;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.mqtt.moquette.ClientDeviceAuthorizer;
import com.aws.greengrass.mqtt.moquette.MQTTService;
import com.aws.greengrass.mqttclient.spool.SpoolerStoreException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import io.moquette.broker.subscriptions.Topic;
import io.moquette.interception.messages.InterceptDisconnectMessage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.NoSuchFileException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith({GGExtension.class, MockitoExtension.class})
public class ClientDeviceAuthorizerIntegrationTest {
    private Kernel kernel;
    private static final String DEFAULT_CLIENT = "myThing";
    private static final String DEFAULT_TOPIC = "topic";
    private static final byte[] DEFAULT_PASSWORD = "".getBytes(StandardCharsets.UTF_8);
    private static final long TEST_TIME_OUT_SEC = 30L;
    @TempDir
    Path rootDir;
    private Optional<String> certId = Optional.of("certId");
    private String clientPem;
    @Mock
    IotAuthClient iotAuthClient;

    @BeforeEach
    void setup(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, SpoolerStoreException.class);
        ignoreExceptionOfType(context, NoSuchFileException.class); // Loading CA keystore
        ignoreExceptionOfType(context, NullPointerException.class); // Uploading Core Device CA
        ignoreExceptionOfType(context, KeyStoreException.class);
        ignoreExceptionOfType(context, UnrecoverableKeyException.class);

        // Set this property for kernel to scan its own classpath to find plugins
        System.setProperty("aws.greengrass.scanSelfClasspath", "true");
        startNucleusWithConfig();

        List<X509Certificate> clientCertificates = CertificateTestHelpersMoquette.createClientCertificates(1);
        this.clientPem = CertificateHelper.toPem(clientCertificates.get(0));
    }

    @AfterEach
    void cleanup() {
        kernel.shutdown();
    }

    void startNucleusWithConfig() throws InterruptedException {
        kernel = new Kernel();
        kernel.getContext().put(IotAuthClient.class, iotAuthClient);

        CountDownLatch serviceRunning = new CountDownLatch(1);
        kernel.parseArgs("-r", rootDir.toAbsolutePath().toString(), "-i",
            getClass().getResource("config.yaml").toString());
        GlobalStateChangeListener listener = (GreengrassService service, State was, State newState) -> {
            if (service.getName().equals(MQTTService.SERVICE_NAME) && service.getState().equals(State.RUNNING)) {
                serviceRunning.countDown();
            }
        };
        kernel.getContext().addGlobalStateChangeListener(listener);
        kernel.launch();
        assertTrue(serviceRunning.await(TEST_TIME_OUT_SEC, TimeUnit.SECONDS));
        kernel.getContext().removeGlobalStateChangeListener(listener);
    }

    @Test
    void GIVEN_duplicate_client_ids_WHEN_check_valid_THEN_can_read_returns_true() {
        ClientDevicesAuthServiceApi clientDevicesAuthServiceApi = kernel.getContext().get(ClientDevicesAuthServiceApi.class);

        ClientDeviceAuthorizer clientDeviceAuthorizer = new ClientDeviceAuthorizer(clientDevicesAuthServiceApi);

        Topic topic = new Topic(DEFAULT_TOPIC);
        Thing thing = new Thing(DEFAULT_CLIENT);
        Certificate cert = new Certificate(this.certId.get());
        when(iotAuthClient.getActiveCertificateId(this.clientPem)).thenReturn(this.certId);
        when(iotAuthClient.isThingAttachedToCertificate(thing, cert)).thenReturn(true);

        assertTrue(clientDeviceAuthorizer.checkValid(DEFAULT_CLIENT, this.clientPem, DEFAULT_PASSWORD));
        assertTrue(clientDeviceAuthorizer.checkValid(DEFAULT_CLIENT, this.clientPem, DEFAULT_PASSWORD));
        assertTrue(clientDeviceAuthorizer.canRead(topic, this.clientPem, DEFAULT_CLIENT));
    }

    @Test
    void GIVEN_authorized_client_WHEN_session_closes_THEN_can_read_returns_true() {
        ClientDevicesAuthServiceApi clientDevicesAuthServiceApi = kernel.getContext().get(ClientDevicesAuthServiceApi.class);

        ClientDeviceAuthorizer clientDeviceAuthorizer = new ClientDeviceAuthorizer(clientDevicesAuthServiceApi);

        ClientDeviceAuthorizer.ConnectionTerminationListener connectionTerminationListener =
            clientDeviceAuthorizer.new ConnectionTerminationListener();

        Topic topic = new Topic(DEFAULT_TOPIC);
        Thing thing = new Thing(DEFAULT_CLIENT);
        Certificate cert = new Certificate(this.certId.get());
        when(iotAuthClient.getActiveCertificateId(this.clientPem)).thenReturn(this.certId);
        when(iotAuthClient.isThingAttachedToCertificate(thing, cert)).thenReturn(true);

        assertTrue(clientDeviceAuthorizer.checkValid(DEFAULT_CLIENT, this.clientPem, DEFAULT_PASSWORD));

        InterceptDisconnectMessage msg = new InterceptDisconnectMessage(DEFAULT_CLIENT, this.clientPem);
        connectionTerminationListener.onDisconnect(msg);

        assertTrue(clientDeviceAuthorizer.canRead(topic, this.clientPem, DEFAULT_CLIENT));
        assertTrue(clientDeviceAuthorizer.checkValid(DEFAULT_CLIENT, this.clientPem, DEFAULT_PASSWORD));
    }
}

