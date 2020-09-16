/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.iot.evergreen.mqtt.broker;
import com.aws.iot.evergreen.certificatemanager.certificate.CertificateRequestGenerator;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.Getter;
import org.bouncycastle.operator.OperatorCreationException;

public class MQTTBrokerKeyStore {
    private static final String DEFAULT_BROKER_CN = "Greengrass MQTT";
    private static final String KEYSTORE_FILE_NAME = "keystore.jks";
    private static final String BROKER_KEY_ALIAS = "pk";

    private final Path rootPath;
    @Getter private final String jksPath;
    @Getter private final String jksPassword;
    private KeyStore brokerKeyStore;
    private KeyPair brokerKeyPair;

    /**
     * MQTTBrokerKeyStore constructor
     * @param rootDir Directory to save KeyStore artifacts.
     */
    public MQTTBrokerKeyStore(Path rootDir) {
        this.rootPath = rootDir;
        this.jksPath = rootDir.resolve(KEYSTORE_FILE_NAME).toString();
        this.jksPassword = generateRandomPassword(16);
    }

    private static String generateRandomPassword(int length) {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom.ints('!', 'z' + 1)
            .limit(length)
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    }

    /**
     * Initializes the MQTTBrokerKeyStore. Must be called prior to using.
     * @throws KeyStoreException Unable to initialize KeyStore.
     */
    public void initialize() throws KeyStoreException {
        // Initialize new keystore rather than loading an old one
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            brokerKeyPair = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException("unable to generate keypair for broker key store", e);
        }

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, jksPassword.toCharArray());
            brokerKeyStore = ks;
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("unable to load broker keystore", e);
        }
    }

    /**
     * Generate CSR from KeyStore private key.
     * @return PEM encoded CSR string
     * @throws IOException IOException
     * @throws OperatorCreationException OperatorCreationException
     */
    public String getCsr() throws IOException, OperatorCreationException {
        return CertificateRequestGenerator.createCSR(brokerKeyPair,
            DEFAULT_BROKER_CN,
            null,
            new ArrayList<>(Arrays.asList("localhost")));
    }

    /**
     * Update KeyStore key certificate.
     * @param certificate Updated certificate
     * @throws KeyStoreException If unable to set key entry.
     */
    public void updateServerCertificate(X509Certificate certificate) throws KeyStoreException {
        Certificate[] certChain = {certificate};
        brokerKeyStore.setKeyEntry(BROKER_KEY_ALIAS,
            brokerKeyPair.getPrivate(),
            jksPassword.toCharArray(),
            certChain);

        try {
            commit();
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            // TODO - properly handle this
            e.printStackTrace();
        }
    }

    /**
     * Update KeyStore with the given CA and device certificates.
     * @param deviceCerts Map of device certificates
     * @param caCerts     List of CA certificates
     * @throws KeyStoreException    If unable to set key entries.
     * @throws IOException          If unable to parse certificates.
     * @throws CertificateException If unable to parse certificates.
     */
    public void updateCertificates(Map<String, String> deviceCerts, List<String> caCerts)
        throws KeyStoreException, IOException, CertificateException {
        // Remove all existing CA certificates and device certificates not included in deviceCerts
        for (String alias : Collections.list(brokerKeyStore.aliases())) {
            if (brokerKeyStore.isCertificateEntry(alias) && !deviceCerts.containsKey(alias)) {
                brokerKeyStore.deleteEntry(alias);
            }
        }

        // Add or update client certs in key store
        for (Map.Entry<String, String> entry : deviceCerts.entrySet()) {
            X509Certificate cert = pemToX509Certificate(entry.getValue());
            brokerKeyStore.setCertificateEntry(entry.getKey(), cert);
        }

        // Add new CA certs
        for (int i = 0; i < caCerts.size(); i++) {
            brokerKeyStore.setCertificateEntry("CA" + i, pemToX509Certificate(caCerts.get(i)));
        }

        try {
            commit();
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            // TODO - properly handle this
            e.printStackTrace();
        }
    }

    private void commit() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        Files.createDirectories(rootPath);
        try (FileOutputStream outputStream = new FileOutputStream(jksPath)) {
            brokerKeyStore.store(outputStream, jksPassword.toCharArray());
        }
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
