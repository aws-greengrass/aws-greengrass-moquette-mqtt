/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.certificatemanager.CertificateManager;
import com.aws.greengrass.certificatemanager.certificate.CsrProcessingException;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.lifecyclemanager.PluginService;
import io.moquette.BrokerConstants;
import io.moquette.broker.ISslContextCreator;
import io.moquette.broker.Server;
import io.moquette.broker.config.IConfig;
import io.moquette.broker.config.MemoryConfig;
import io.moquette.interception.InterceptHandler;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import javax.inject.Inject;

@ImplementsService(name = MQTTService.SERVICE_NAME, autostart = true)
public class MQTTService extends PluginService {
    public static final String SERVICE_NAME = "aws.greengrass.clientdevices.mqtt.Moquette";

    private static BrokerKeyStore brokerKeyStore;
    private final Server mqttBroker = new Server();
    private final Kernel kernel;
    private final CertificateManager certificateManager;
    private final ClientDeviceTrustManager clientDeviceTrustManager;
    private final ClientDeviceAuthorizer clientDeviceAuthorizer;
    private final List<InterceptHandler> interceptHandlers;

    private boolean serverRunning = false;

    /**
     * Constructor for GreengrassService.
     *
     * @param topics             Root Configuration topic for this service
     * @param kernel             Greengrass Nucleus
     * @param certificateManager Client devices auth's certificate manager
     * @param deviceAuthClient   Client device auth client
     */
    @Inject
    public MQTTService(Topics topics, Kernel kernel, CertificateManager certificateManager,
                       DeviceAuthClient deviceAuthClient) {
        super(topics);
        this.kernel = kernel;
        this.certificateManager = certificateManager;
        this.clientDeviceTrustManager = new ClientDeviceTrustManager(deviceAuthClient);
        this.clientDeviceAuthorizer = new ClientDeviceAuthorizer(clientDeviceTrustManager, deviceAuthClient);
        this.interceptHandlers = Collections.singletonList(clientDeviceAuthorizer.new ConnectionTerminationListener());
    }

    @Override
    protected void install() {
        try {
            brokerKeyStore = new BrokerKeyStore(kernel.getNucleusPaths().workPath(SERVICE_NAME));
            brokerKeyStore.initialize();
        } catch (IOException | KeyStoreException e) {
            serviceErrored(e);
        }
    }

    private synchronized void updateServerCertificate(X509Certificate cert) {
        try {
            brokerKeyStore.updateServerCertificate(cert);
        } catch (KeyStoreException e) {
            logger.atError().cause(e).log("Failed to update MQTT broker certificate");
        }
        restartMqttServer();
    }

    @Override
    public synchronized void startup() {
        // Subscribe to client devices auth certificate updates
        try {
            String brokerCsr = brokerKeyStore.getCsr();
            certificateManager.subscribeToServerCertificateUpdates(brokerCsr, this::updateServerCertificate);
        } catch (KeyStoreException | CsrProcessingException | OperatorCreationException | IOException e) {
            logger.atError().log("Unable to generate MQTT broker certificate");
            serviceErrored(e);
            return;
        }

        IConfig config = getDefaultConfig();
        ISslContextCreator sslContextCreator =
            new GreengrassMoquetteSslContextCreator(config, clientDeviceTrustManager);
        mqttBroker
            .startServer(config, interceptHandlers, sslContextCreator, clientDeviceAuthorizer, clientDeviceAuthorizer);
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
                new GreengrassMoquetteSslContextCreator(config, clientDeviceTrustManager);
            mqttBroker.startServer(config, interceptHandlers, sslContextCreator, clientDeviceAuthorizer,
                clientDeviceAuthorizer);
        }
    }

    private IConfig getDefaultConfig() {
        // TODO - Make configurable
        IConfig defaultConfig = new MemoryConfig(new Properties());

        String password = brokerKeyStore.getJksPassword();
        defaultConfig.setProperty(BrokerConstants.SSL_PORT_PROPERTY_NAME, "8883");
        defaultConfig.setProperty(BrokerConstants.JKS_PATH_PROPERTY_NAME, brokerKeyStore.getJksPath());
        defaultConfig.setProperty(BrokerConstants.KEY_STORE_PASSWORD_PROPERTY_NAME, password);
        defaultConfig.setProperty(BrokerConstants.KEY_MANAGER_PASSWORD_PROPERTY_NAME, password);
        defaultConfig.setProperty(BrokerConstants.ALLOW_ANONYMOUS_PROPERTY_NAME, "false");
        defaultConfig.setProperty(BrokerConstants.NEED_CLIENT_AUTH, "true");
        defaultConfig.setProperty(BrokerConstants.IMMEDIATE_BUFFER_FLUSH_PROPERTY_NAME, "true");
        defaultConfig.setProperty(BrokerConstants.NETTY_ENABLED_TLS_PROTOCOLS_PROPERTY_NAME, "TLSv1.2");

        //Disable plain TCP port
        defaultConfig.setProperty(BrokerConstants.PORT_PROPERTY_NAME, BrokerConstants.DISABLED_PORT_BIND);

        return defaultConfig;
    }
}
