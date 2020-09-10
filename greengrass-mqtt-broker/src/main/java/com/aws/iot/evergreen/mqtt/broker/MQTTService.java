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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
    private static final String ALLOW_ANONYMOUS = "true";
    private static final String ENFORCE_CLIENT_AUTH = "true";

    // Config Keys
    private static final String CONFIG_TOPIC = "config";
    private static final String CERTIFICATES_TOPIC = "certificates";
    private static final String CLIENT_CERTS = "clients";
    // TODO: Is this the right key?
    private static final String RUNTIME_CONFIG_KEY = "runtime";

    // Key store properties
    private static final String DEFAULT_BROKER_CN = "greengrass-mqtt-broker";
    private static final String BROKER_KEY_ALIAS = "MqttBroker";
    private static final String KEYSTORE_PASSWORD_STRING = MQTTBrokerKeyStore.DEFAULT_KEYSTORE_PASSWORD_STRING;

    private static MQTTBrokerKeyStore mqttBrokerKeyStore;
    private static KeyStore brokerKeyStore;
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

    private void configureKeyStore() throws
        KeyStoreException, CsrProcessingException {
        // get basic keystore from KeyStore
        mqttBrokerKeyStore = new MQTTBrokerKeyStore();
        brokerKeyStore = mqttBrokerKeyStore.getKeyStore();

        // Subscribe to broker cert updates from DCM
        subscribeToBrokerCert();
        // Subscribe to client cert updates from DCM
        Topics dcmConfig = kernel.findServiceTopic(DCM_SERVICE_NAME);
        if (dcmConfig != null) {
            dcmConfig.lookup(RUNTIME_CONFIG_KEY, CONFIG_TOPIC, CERTIFICATES_TOPIC, CLIENT_CERTS)
                .subscribe(this::onClientCertsChange);
        }
    }

    private void subscribeToBrokerCert() throws KeyStoreException, CsrProcessingException {

        String csr;
        try {
            csr = CertificateRequestGenerator.createCSR(MQTTBrokerKeyStore.getBrokerKeyPair(),
                DEFAULT_BROKER_CN,
                null,
                null);
        } catch (IOException | OperatorCreationException e) {
            throw new KeyStoreException("unable to generate CSR from keypair", e);
        }
        certificateManager.subscribeToCertificateUpdates(csr, this::updateCertInKeyStore);
    }

    private void onClientCertsChange(WhatHappened whatHappened, Topic topic) {
        Topic certs = this.config.lookup(RUNTIME_CONFIG_KEY,
            CONFIG_TOPIC,
            CERTIFICATES_TOPIC,
            CLIENT_CERTS).dflt("[]");
        Map<String, String> clientCerts;
        String val = Coerce.toString(certs);

        if (val != null) {
            try {
                clientCerts = OBJECT_MAPPER.readValue(val, new TypeReference<Map<String, String>>() { });
                // import client certs to keystore
                importClientCertsIntoKeyStore(clientCerts);
            } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
                logger.atError().kv("node", certs.getFullName()).kv("value", val)
                    .log("Malformed client certs", e);
            }
        }
    }

    private void updateCertInKeyStore(String certPem) {
        try {
            X509Certificate cert = pemToX509Certificate(certPem);
            Certificate[] certChain = {cert};
            brokerKeyStore.setKeyEntry(BROKER_KEY_ALIAS,
                MQTTBrokerKeyStore.getBrokerKeyPair().getPrivate(),
                MQTTBrokerKeyStore.DEFAULT_KEYSTORE_PASSWORD,
                certChain);
            // stop mqtt server, write keystore back to disk and restart server
            restartMqttServer();
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            //consumer can only throw runtime exception
            throw new RuntimeException("unable to store generated cert", e);
        }
    }

    private KeyStore importClientCertsIntoKeyStore(Map<String, String> clientCerts)
        throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        // Remove deleted client certs from key store
        for (String alias : Collections.list(brokerKeyStore.aliases())) {
            if (!alias.equals(BROKER_KEY_ALIAS) && !clientCerts.containsKey(alias)) {
                brokerKeyStore.deleteEntry(alias);
            }
        }

        // Add or update client certs in key store
        for (Map.Entry<String, String> entry : clientCerts.entrySet()) {
            X509Certificate cert = pemToX509Certificate(entry.getValue());
            brokerKeyStore.setCertificateEntry(entry.getKey(), cert);
        }
        // stop mqtt server, write keystore back to disk and restart server
        restartMqttServer();
        return brokerKeyStore;
    }

    private void restartMqttServer() throws
        IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        mqttBroker.stopServer();
        mqttBrokerKeyStore.writeKeyStoreToDisk(brokerKeyStore);
        mqttBroker.startServer();
    }

    private IConfig getDefaultConfig() {
        // TODO: Enable SSL, get certs from DCM
        IConfig defaultConfig = new MemoryConfig(new Properties());

        defaultConfig.setProperty(BrokerConstants.SSL_PORT_PROPERTY_NAME, SSL_PORT);
        defaultConfig.setProperty(BrokerConstants.JKS_PATH_PROPERTY_NAME, mqttBrokerKeyStore.getBrokerKeyStorePath());
        defaultConfig.setProperty(BrokerConstants.KEY_STORE_PASSWORD_PROPERTY_NAME, KEYSTORE_PASSWORD_STRING);
        defaultConfig.setProperty(BrokerConstants.KEY_MANAGER_PASSWORD_PROPERTY_NAME, KEYSTORE_PASSWORD_STRING);
        defaultConfig.setProperty(BrokerConstants.ALLOW_ANONYMOUS_PROPERTY_NAME, ALLOW_ANONYMOUS);
        defaultConfig.setProperty(BrokerConstants.NEED_CLIENT_AUTH, ENFORCE_CLIENT_AUTH);

        return defaultConfig;
    }

    private X509Certificate pemToX509Certificate(String certPem) throws IOException, CertificateException {
        byte[] certBytes = certPem.getBytes(StandardCharsets.UTF_8);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (InputStream certStream = new ByteArrayInputStream(certBytes)) {
            cert = (X509Certificate) certFactory.generateCertificate(certStream);
        }
        return cert;
    }
}
