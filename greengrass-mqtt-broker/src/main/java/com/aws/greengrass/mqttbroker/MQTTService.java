/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.certificatemanager.CertificateManager;
import com.aws.greengrass.certificatemanager.certificate.CsrProcessingException;
import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.config.WhatHappened;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.lifecyclemanager.PluginService;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.SerializerFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import io.moquette.BrokerConstants;
import io.moquette.broker.ISslContextCreator;
import io.moquette.broker.Server;
import io.moquette.broker.config.IConfig;
import io.moquette.broker.config.MemoryConfig;
import io.moquette.broker.security.IAuthenticator;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.inject.Inject;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

@ImplementsService(name = MQTTService.SERVICE_NAME, autostart = true)
public class MQTTService extends PluginService {
    public static final String SERVICE_NAME = "aws.greengrass.clientdevices.Mqtt.Moquette";
    public static final String DCM_SERVICE_NAME = "aws.greengrass.CertificateManager";

    // Config Keys
    private static final String RUNTIME_CONFIG_KEY = "runtime";
    private static final String CERTIFICATES_KEY = "certificates";
    private static final String AUTHORITIES_TOPIC = "authorities";
    private static final String DEVICES_TOPIC = "devices";

    private static MQTTBrokerKeyStore mqttBrokerKeyStore;
    private final Server mqttBroker = new Server();
    private final Kernel kernel;
    private final CertificateManager certificateManager;
    private final IAuthenticator authenticator = new CertificateAuthenticator();
    private final TrustManager allowAllTrustManager = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    private boolean serverRunning = false;

    /**
     * Constructor for GreengrassService.
     *
     * @param topics             Root Configuration topic for this service
     * @param kernel             Greengrass Nucleus
     * @param certificateManager DCM's certificate manager
     */
    @Inject
    public MQTTService(Topics topics, Kernel kernel, CertificateManager certificateManager) {
        super(topics);
        this.kernel = kernel;
        this.certificateManager = certificateManager;
    }

    @Override
    protected void install() {
        try {
            mqttBrokerKeyStore = new MQTTBrokerKeyStore(kernel.getNucleusPaths().workPath(SERVICE_NAME));
            mqttBrokerKeyStore.initialize();
        } catch (IOException | KeyStoreException e) {
            serviceErrored(e);
        }
    }

    private synchronized void updateServerCertificate(X509Certificate cert) {
        try {
            mqttBrokerKeyStore.updateServerCertificate(cert);
        } catch (KeyStoreException e) {
            logger.atError().cause(e).log("failed to update MQTT server certificate");
        }
        restartMqttServer();
    }

    @SuppressWarnings("PMD.UnusedFormalParameter")
    private synchronized void updateCertificates(WhatHappened what, Topic topic) {
        if (WhatHappened.timestampUpdated.equals(what) || WhatHappened.interiorAdded.equals(what)) {
            return;
        }
        Topics dcmTopics = kernel.findServiceTopic(DCM_SERVICE_NAME);

        String serializedDeviceCerts =
            Coerce.toString(dcmTopics.lookup(RUNTIME_CONFIG_KEY, CERTIFICATES_KEY, DEVICES_TOPIC));
        if (serializedDeviceCerts == null) {
            return;
        }
        TypeReference<HashMap<String, String>> typeRef = new TypeReference<HashMap<String, String>>() {
        };
        Map<String, String> deviceCerts;
        try {
            deviceCerts = SerializerFactory.getFailSafeJsonObjectMapper().readValue(serializedDeviceCerts, typeRef);
        } catch (JsonProcessingException e) {
            logger.atError().cause(e).log("failed to parse device certificates");
            deviceCerts = Collections.emptyMap();
        }

        try {
            List<String> caCerts =
                (List<String>) dcmTopics.lookup(RUNTIME_CONFIG_KEY, CERTIFICATES_KEY, AUTHORITIES_TOPIC).toPOJO();
            mqttBrokerKeyStore.updateCertificates(deviceCerts, caCerts);
        } catch (KeyStoreException | IOException | CertificateException e) {
            logger.atError().cause(e).log("failed to update device and CA certificates");
        }
        restartMqttServer();
    }

    @Override
    public synchronized void startup() {
        // Subscribe to DCM certificate updates
        try {
            String brokerCsr = mqttBrokerKeyStore.getCsr();
            certificateManager.subscribeToServerCertificateUpdates(brokerCsr, this::updateServerCertificate);
        } catch (KeyStoreException | CsrProcessingException | OperatorCreationException | IOException e) {
            logger.atError().log("unable to generate broker certificate");
            serviceErrored(e);
            return;
        }

        // Subscribe to CA and device certificate updates
        Topics dcmTopics = kernel.findServiceTopic(DCM_SERVICE_NAME);
        dcmTopics.lookup(RUNTIME_CONFIG_KEY, CERTIFICATES_KEY, AUTHORITIES_TOPIC).subscribe(this::updateCertificates);
        dcmTopics.lookup(RUNTIME_CONFIG_KEY, CERTIFICATES_KEY, DEVICES_TOPIC).subscribe(this::updateCertificates);

        IConfig config = getDefaultConfig();
        ISslContextCreator sslContextCreator = new GreengrassMoquetteSslContextCreator(config, allowAllTrustManager);
        mqttBroker.startServer(config, null, sslContextCreator, authenticator, null);
        serverRunning = true;
        reportState(State.RUNNING);
    }

    @Override
    public synchronized void shutdown() {
        if (serverRunning) {
            mqttBroker.stopServer();
            serverRunning = false;
        }
    }

    private synchronized void restartMqttServer() {
        if (serverRunning) {
            mqttBroker.stopServer();
            IConfig config = getDefaultConfig();
            ISslContextCreator sslContextCreator =
                new GreengrassMoquetteSslContextCreator(config, allowAllTrustManager);
            mqttBroker.startServer(config, null, sslContextCreator, authenticator, null);
        }
    }

    private IConfig getDefaultConfig() {
        // TODO - Make configurable
        IConfig defaultConfig = new MemoryConfig(new Properties());

        String password = mqttBrokerKeyStore.getJksPassword();
        defaultConfig.setProperty(BrokerConstants.SSL_PORT_PROPERTY_NAME, "8883");
        defaultConfig.setProperty(BrokerConstants.JKS_PATH_PROPERTY_NAME, mqttBrokerKeyStore.getJksPath());
        defaultConfig.setProperty(BrokerConstants.KEY_STORE_PASSWORD_PROPERTY_NAME, password);
        defaultConfig.setProperty(BrokerConstants.KEY_MANAGER_PASSWORD_PROPERTY_NAME, password);
        defaultConfig.setProperty(BrokerConstants.ALLOW_ANONYMOUS_PROPERTY_NAME, "true");
        defaultConfig.setProperty(BrokerConstants.NEED_CLIENT_AUTH, "true");

        //Disable plain TCP port
        defaultConfig.setProperty(BrokerConstants.PORT_PROPERTY_NAME, BrokerConstants.DISABLED_PORT_BIND);

        return defaultConfig;
    }
}