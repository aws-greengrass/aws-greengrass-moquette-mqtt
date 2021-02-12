/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt;

import com.aws.greengrass.certificatemanager.CertificateManager;
import com.aws.greengrass.certificatemanager.DCMService;
import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.testcommons.testutilities.GGServiceTestUtil;
import io.moquette.BrokerConstants;
import io.moquette.broker.Server;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.ConnectException;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    private void startKernelWithMQTTBroker() throws InterruptedException {
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
    }

    @Test
    void GIVEN_Greengrass_with_broker_WHEN_start_nucleus_THEN_broker_starts_on_port_8883()
        throws InterruptedException, IOException {
        startKernelWithMQTTBroker();

        // Connect to port 8883 just to confirm server is listening on port
        Socket socket = new Socket("localhost", 8883);
        socket.close();
    }

    @Test
    void GIVEN_Greengrass_with_broker_WHEN_start_nucleus_THEN_broker_doesnt_start_on_plain_tcp_port()
        throws InterruptedException {
        startKernelWithMQTTBroker();

        assertThrows(ConnectException.class, () -> {
            new Socket("localhost", BrokerConstants.PORT);
        });
    }

    @Test
    void GIVEN_Greengrass_with_mqtt_broker_WHEN_encryption_type_updated_THEN_KeyStore_updated() throws Exception {
        startKernelWithMQTTBroker();

        MQTTService mqttService = (MQTTService) kernel.locate(MQTTService.SERVICE_NAME);
        KeyPair initialKey = mqttService.getMqttBrokerKeyStore().getBrokerKeyPair();
        assertThat(initialKey.getPrivate().getAlgorithm(), is("RSA"));

        kernel.locate(MQTTService.SERVICE_NAME).getConfig()
            .find(CONFIGURATION_CONFIG_KEY, MQTTService.ENCRYPTION_TOPIC).withValue("EC");
        // Block until subscriber has finished updating
        kernel.getContext().runOnPublishQueueAndWait(() -> {
        });

        KeyPair secondKey = mqttService.getMqttBrokerKeyStore().getBrokerKeyPair();
        assertThat(secondKey.getPrivate().getAlgorithm(), is("EC"));
        assertThat(secondKey, is(not(initialKey)));
    }

    @Test
    void GIVEN_Greengrass_with_mqtt_broker_WHEN_CA_and_device_certs_updated_THEN_KeyStore_updated() throws Exception {
        serviceFullName = MQTTService.SERVICE_NAME;
        initializeMockedConfig();
        Kernel mockKernel = mock(Kernel.class);
        MQTTBrokerKeyStore mockMqttBrokerKeyStore = mock(MQTTBrokerKeyStore.class);
        when(mockMqttBrokerKeyStore.getJksPath()).thenReturn("testPath");
        when(mockMqttBrokerKeyStore.getJksPassword()).thenReturn("testPassword");
        CertificateManager mockCertificateManager = mock(CertificateManager.class);
        Server mockServer = mock(Server.class);
        MQTTService mqttService = new MQTTService(config, mockKernel, mockCertificateManager,
            mockMqttBrokerKeyStore, mockServer);

        Topic encryptionTopic = Topic.of(context, "encryption", "RSA");
        when(config.lookup(CONFIGURATION_CONFIG_KEY, "encryption")).thenReturn(encryptionTopic);
        Topics mockDCMConfig = mock(Topics.class);
        when(mockKernel.findServiceTopic(DCMService.DCM_SERVICE_NAME)).thenReturn(mockDCMConfig);

        Topic caTopic = Topic.of(context, "authorities", Arrays.asList("CA1", "CA2"));
        when(mockDCMConfig.lookup(MQTTService.RUNTIME_STORE_NAMESPACE_TOPIC, DCMService.CERTIFICATES_KEY,
            DCMService.AUTHORITIES_TOPIC)).thenReturn(caTopic);
        Topic deviceTopic = Topic.of(context, "devices", "{\"device1\":\"cert1\",\"device2\":\"cert2\"}");
        when(mockDCMConfig.lookup(MQTTService.RUNTIME_STORE_NAMESPACE_TOPIC, DCMService.CERTIFICATES_KEY,
            DCMService.DEVICES_TOPIC)).thenReturn(deviceTopic);

        mqttService.startup();
        mqttService.shutdown();
        ArgumentCaptor<List<String>> caListCaptor = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<Map<String, String>> deviceMapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockMqttBrokerKeyStore, atLeastOnce())
            .updateCertificates(deviceMapCaptor.capture(), caListCaptor.capture());
        assertThat(caListCaptor.getValue(), is(Arrays.asList("CA1", "CA2")));
        Map<String, String> expectedDeviceMap = new HashMap<String, String>() {{
            put("device1", "cert1");
            put("device2", "cert2");
        }};
        assertThat(deviceMapCaptor.getValue(), is(expectedDeviceMap));
    }
}
