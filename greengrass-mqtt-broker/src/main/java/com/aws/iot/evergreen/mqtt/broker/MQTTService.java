/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.iot.evergreen.mqtt.broker;

import com.aws.iot.evergreen.config.Topic;
import com.aws.iot.evergreen.config.WhatHappened;
import com.aws.iot.evergreen.dcm.certificate.CertificateManager;
import com.aws.iot.evergreen.dcm.certificate.CertificateRequestGenerator;
import com.aws.iot.evergreen.config.Topics;
import com.aws.iot.evergreen.dcm.certificate.CsrProcessingException;
import com.aws.iot.evergreen.dependency.ImplementsService;
import com.aws.iot.evergreen.dependency.State;
import com.aws.iot.evergreen.kernel.EvergreenService;

import com.aws.iot.evergreen.kernel.Kernel;
import com.aws.iot.evergreen.util.Coerce;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.moquette.BrokerConstants;
import io.moquette.broker.Server;
import io.moquette.broker.config.IConfig;
import io.moquette.broker.config.MemoryConfig;

import javax.inject.Inject;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import org.bouncycastle.operator.OperatorCreationException;

@ImplementsService(name = MQTTService.SERVICE_NAME, autostart = true)
public class MQTTService extends EvergreenService {
    public static final String SERVICE_NAME = "aws.greengrass.mqtt";
    public static final String DCM_SERVICE_NAME = "aws.greengrass.certificate.manager";
    private static final JsonMapper OBJECT_MAPPER =
        JsonMapper.builder().configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true).build();

    // Moquette Properties
    private static final String SSL_PORT = "8883";
    private static final String ENFORCE_CLIENT_AUTH = "true";

    // Config Keys
    private static final String RUNTIME_CONFIG_KEY = "runtime";
    private static final String CERTIFICATES_TOPIC = "certificates";
    private static final String DEVICES_TOPIC = "devices";

    // Key store properties
    private static final String DEFAULT_BROKER_CN = "greengrass-mqtt-broker";

    private static MQTTBrokerKeyStore mqttBrokerKeyStore;
    private final Server mqttBroker = new Server();
    private final Kernel kernel;
    private final CertificateManager certificateManager;

    /**
     * Constructor for EvergreenService.
     *
     * @param topics Root Configuration topic for this service
     * @param kernel evergreen kernel
     * @param certificateManager DCM's certificate manager
     */
    @Inject
    public MQTTService(Topics topics, Kernel kernel, CertificateManager certificateManager) {
        super(topics);
        this.kernel = kernel;
        this.certificateManager = certificateManager;
    }

    @Override
    public void startup() {
        try {
            configureKeyStore();
            mqttBroker.startServer(getDefaultConfig());
        } catch (IOException | KeyStoreException | CsrProcessingException e) {
            serviceErrored(e);
            return;
        }
        reportState(State.RUNNING);
    }

    @Override
    public void shutdown() {
        mqttBroker.stopServer();
    }

    private void configureKeyStore() throws KeyStoreException, CsrProcessingException {
        // get basic keystore from KeyStore
        mqttBrokerKeyStore = new MQTTBrokerKeyStore(kernel.getWorkPath());
        KeyPair brokerKeyPair = mqttBrokerKeyStore.getBrokerKeyPair();

        // Generate CSR and subscribe to certificate updates from DCM
        String csr;
        try {
            csr = CertificateRequestGenerator.createCSR(brokerKeyPair, DEFAULT_BROKER_CN,null, null);
        } catch (IOException | OperatorCreationException e) {
            throw new KeyStoreException("unable to generate CSR from keypair", e);
        }
        certificateManager.subscribeToCertificateUpdates(csr, this::updateCertificate);

        // Subscribe to device certificate updates from DCM
        Topics dcmConfig = kernel.findServiceTopic(DCM_SERVICE_NAME);
        if (dcmConfig != null) {
            dcmConfig.lookup(RUNTIME_CONFIG_KEY, CERTIFICATES_TOPIC, DEVICES_TOPIC)
                .subscribe(this::updateDeviceCertificates);
        }
    }

    private void updateCertificate(X509Certificate cert) {
        try {
            // stop mqtt server, update key store and restart server
            mqttBroker.stopServer();
            mqttBrokerKeyStore.updateCertificateInKeyStore(cert);
            mqttBroker.startServer();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            //consumer can only throw runtime exception
            throw new RuntimeException("unable to store generated cert", e);
        }
    }

    private void updateDeviceCertificates(WhatHappened whatHappened, Topic topic) {
        Topic certs = this.config.lookup(RUNTIME_CONFIG_KEY, CERTIFICATES_TOPIC, DEVICES_TOPIC).dflt("[]");
        Map<String, String> clientCerts;
        String val = Coerce.toString(certs);

        if (val != null) {
            try {
                clientCerts = OBJECT_MAPPER.readValue(val, new TypeReference<Map<String, String>>() { });
                // stop mqtt server, update client certs to key store and restart server
                mqttBroker.stopServer();
                mqttBrokerKeyStore.updateDeviceCertificatesInKeyStore(clientCerts);
                mqttBroker.startServer();
            } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
                logger.atError().kv("node", certs.getFullName()).kv("value", val)
                    .log("Malformed client certs", e);
            }
        }
    }

    private IConfig getDefaultConfig() {
        // TODO: Enable SSL, get certs from DCM
        IConfig defaultConfig = new MemoryConfig(new Properties());

        defaultConfig.setProperty(BrokerConstants.SSL_PORT_PROPERTY_NAME, SSL_PORT);
        defaultConfig.setProperty(BrokerConstants.JKS_PATH_PROPERTY_NAME, mqttBrokerKeyStore.getKeyStorePath());
        defaultConfig.setProperty(BrokerConstants.KEY_STORE_PASSWORD_PROPERTY_NAME, mqttBrokerKeyStore.getStorePassword());
        defaultConfig.setProperty(BrokerConstants.KEY_MANAGER_PASSWORD_PROPERTY_NAME, mqttBrokerKeyStore.getStorePassword());
        defaultConfig.setProperty(BrokerConstants.NEED_CLIENT_AUTH, ENFORCE_CLIENT_AUTH);

        return defaultConfig;
    }
}
