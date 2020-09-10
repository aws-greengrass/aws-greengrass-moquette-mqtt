/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.iot.evergreen.mqtt.broker;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;

import javax.inject.Inject;

public class MQTTBrokerKeyStore {

    private static final int RSA_KEY_LENGTH = 2048;
    private static final String RSA_KEY_INSTANCE = "RSA";
    private static final char[] DEFAULT_KEYSTORE_PASSWORD = "".toCharArray();

    private final String keyStorePath;
    private final char[] keyStorePassword;
    private static KeyStore brokerKeyStore;
    private KeyPair brokerKeyPair;

    @Inject
    public MQTTBrokerKeyStore(Path workDirPath) throws KeyStoreException {
        keyStorePath = workDirPath + "/" + MQTTService.SERVICE_NAME + "/serverstore.jks";
        keyStorePassword = DEFAULT_KEYSTORE_PASSWORD;
        brokerKeyStore = initializeKeyStore();
    }

    // getter
    KeyPair getBrokerKeyPair() {
        return brokerKeyPair;
    }

    // getter
    String getKeyStorePath() {
        return keyStorePath;
    }

    // getter
    String getStorePassword() {
        return String.valueOf(keyStorePassword);
    }

    void updateCertificateInKeyStore(X509Certificate cert) throws
        CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        try {
            Certificate[] certChain = {cert};
            brokerKeyStore.setKeyEntry("MqttBroker",getBrokerKeyPair().getPrivate(),
                keyStorePassword,
                certChain);
        } catch (KeyStoreException e) {
            //consumer can only throw runtime exception
            throw new RuntimeException("unable to store generated cert", e);
        }

        writeKeyStoreToDisk(brokerKeyStore);
    }

    void updateDeviceCertificatesInKeyStore(Map<String, String> deviceCertificateList)
        throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        // Remove deleted client certs from key store
        for (String alias : Collections.list(brokerKeyStore.aliases())) {
            if (!brokerKeyStore.isKeyEntry(alias) && !deviceCertificateList.containsKey(alias)) {
                brokerKeyStore.deleteEntry(alias);
            }
        }

        // Add or update client certs in key store
        for (Map.Entry<String, String> entry : deviceCertificateList.entrySet()) {
            X509Certificate cert = pemToX509Certificate(entry.getValue());
            brokerKeyStore.setCertificateEntry(entry.getKey(), cert);
        }

        writeKeyStoreToDisk(brokerKeyStore);
    }

    private KeyStore initializeKeyStore() throws KeyStoreException {
        try {
            brokerKeyStore = loadBrokerKeyStore();
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            brokerKeyStore = createDefaultBrokerKeyStore();
        }
        return brokerKeyStore;
    }

    private KeyStore loadBrokerKeyStore() throws
        KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream is = new FileInputStream(keyStorePath)) {
            keystore.load(is, keyStorePassword);
            return keystore;
        }
    }

    private KeyStore createDefaultBrokerKeyStore() throws KeyStoreException {
        // Generate Broker keypair
        try {
            brokerKeyPair = newRSAKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException("unable to generate keypair for broker key store", e);
        }

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, keyStorePassword);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("unable to load broker keystore", e);
        }
        return ks;
    }

    private void writeKeyStoreToDisk(KeyStore keyStore) throws
        IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        try (FileOutputStream outputStream = new FileOutputStream(keyStorePath)) {
            keyStore.store(outputStream, keyStorePassword);
        }
    }

    private static KeyPair newRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_KEY_INSTANCE);
        kpg.initialize(RSA_KEY_LENGTH);
        return kpg.generateKeyPair();
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
