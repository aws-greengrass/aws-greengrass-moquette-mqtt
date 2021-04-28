/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.certificatemanager.certificate.CertificateRequestGenerator;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.util.Utils;
import lombok.Getter;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class BrokerKeyStore {
    private static final Logger LOGGER = LogManager.getLogger(BrokerKeyStore.class);
    private static final String DEFAULT_BROKER_CN = MQTTService.SERVICE_NAME;
    private static final String KEYSTORE_FILE_NAME = "keystore.jks";
    private static final String BROKER_KEY_ALIAS = "pk";

    private final Path rootPath;
    @Getter
    private final String jksPath;
    @Getter
    private final String jksPassword;
    private KeyStore jks;
    private KeyPair jksKeyPair;

    /**
     * MQTTBrokerKeyStore constructor.
     *
     * @param rootDir Directory to save KeyStore artifacts.
     */
    public BrokerKeyStore(Path rootDir) {
        this.rootPath = rootDir;
        this.jksPath = rootDir.resolve(KEYSTORE_FILE_NAME).toString();
        this.jksPassword = generateRandomPassword(16);
    }

    private static String generateRandomPassword(int length) {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom.ints('!', 'z' + 1).limit(length)
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
    }

    /**
     * Initializes the MQTTBrokerKeyStore. Must be called prior to using.
     *
     * @throws KeyStoreException Unable to initialize KeyStore.
     */
    public void initialize() throws KeyStoreException {
        // Initialize new keystore rather than loading an old one
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            jksKeyPair = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException("unable to generate keypair for broker key store", e);
        }

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, jksPassword.toCharArray());
            jks = ks;
            commit();
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("unable to load broker keystore", e);
        }
    }

    /**
     * Generate CSR from KeyStore private key.
     *
     * @return PEM encoded CSR string
     * @throws IOException               IOException
     * @throws OperatorCreationException OperatorCreationException
     */
    public String getCsr() throws IOException, OperatorCreationException {
        return CertificateRequestGenerator
            .createCSR(jksKeyPair, DEFAULT_BROKER_CN, null, getHostIpAddresses());
    }

    //TODO delete me after beta release
    private List<String> getHostIpAddresses() throws SocketException {
        List<String> ipAddresses = new ArrayList<>();
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface ni = networkInterfaces.nextElement();
            Enumeration<InetAddress> inetAddresses = ni.getInetAddresses();
            while (inetAddresses.hasMoreElements()) {
                ipAddresses.add(inetAddresses.nextElement().getHostAddress());
            }
        }
        return Collections.unmodifiableList(ipAddresses);
    }

    /**
     * Update KeyStore key certificate.
     *
     * @param certificate Updated certificate
     * @throws KeyStoreException If unable to set key entry.
     */
    public void updateServerCertificate(X509Certificate certificate) throws KeyStoreException {
        Certificate[] certChain = {certificate};
        jks.setKeyEntry(BROKER_KEY_ALIAS, jksKeyPair.getPrivate(), jksPassword.toCharArray(), certChain);

        try {
            commit();
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            // TODO - properly handle this
            LOGGER.atError().log(e);
        }
    }

    private void commit() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        Utils.createPaths(rootPath);
        try (OutputStream outputStream = Files.newOutputStream(Paths.get(jksPath))) {
            jks.store(outputStream, jksPassword.toCharArray());
        }
    }
}
