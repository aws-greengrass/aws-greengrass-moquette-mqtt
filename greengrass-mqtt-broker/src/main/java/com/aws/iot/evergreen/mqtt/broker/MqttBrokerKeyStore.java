/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */

package com.aws.iot.evergreen.mqtt.broker;

import com.aws.iot.evergreen.dcm.certificate.CertificateRequestGenerator;
import com.aws.iot.evergreen.dcm.certificate.CertificateManager;
import com.aws.iot.evergreen.dcm.certificate.CsrProcessingException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import lombok.AccessLevel;
import lombok.Getter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.List;
import org.bouncycastle.operator.OperatorCreationException;

import javax.inject.Inject;

public class MqttBrokerKeyStore {

    private static final char[] DEFAULT_KEYSTORE_PASSWORD = "".toCharArray();
    private static final String DEFAULT_BROKER_CN = "greengrass-mqtt-broker";
    private static final String BROKER_KEY_ALIAS = "MqttBroker";

    private static final String RSA_KEY_INSTANCE = "RSA";
    private static final int    RSA_KEY_LENGTH = 2048;

    @Getter(AccessLevel.PACKAGE)
    private KeyStore brokerKeyStore;

    private final CertificateManager certificateManager;
    private static KeyPair brokerKeyPair;

    @Inject
    public MqttBrokerKeyStore(CertificateManager certificateManager) {
        this.certificateManager = certificateManager;
    }

    /**
     *
     * @param clientCerts
     * @return
     * @throws CertificateException
     * @throws KeyStoreException if unable to generate keypair or load keystore
     * @throws IOException if unable to convert cert pem to X509Certificate
     * @throws CsrProcessingException if unable to subscribe with csr
     *
     */
    public KeyStore getBrokerKeyStore(List<String> clientCerts)
        throws CertificateException, KeyStoreException, IOException, CsrProcessingException {
        try {
            brokerKeyStore = loadBrokerKeyStore();
        } catch (KeyStoreException e) {
            brokerKeyStore = createDefaultBrokerKeyStore();
        }

        // Import client certs to key store
        brokerKeyStore = importClientCertsIntoKeyStore(clientCerts);
        return brokerKeyStore;
    }

    private KeyStore createDefaultBrokerKeyStore() throws KeyStoreException, CsrProcessingException {
        // Generate Broker keypair
        try {
            brokerKeyPair = newRSAKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException("unable to generate keypair for broker key store", e);
        }

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, DEFAULT_KEYSTORE_PASSWORD);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("unable to load broker keystore", e);
        }

        String csr;
        try {
            // TODO: do we need IP here?
            csr = CertificateRequestGenerator.createCSR(brokerKeyPair, DEFAULT_BROKER_CN, null,  null);
        } catch (IOException | OperatorCreationException e) {
            throw new KeyStoreException("unable to generate CSR from keypair", e);
        }

        certificateManager.subscribeToCertificateUpdates(csr, this::updateCertInKeyStore);
        return ks;
    }

    private static KeyPair newRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_KEY_INSTANCE);
        kpg.initialize(RSA_KEY_LENGTH);
        return kpg.generateKeyPair();
    }

    private void updateCertInKeyStore(String certPem) {
        try {
            X509Certificate cert = pemToX509Certificate(certPem);
            Certificate[] certChain = {cert};
            brokerKeyStore.setKeyEntry(BROKER_KEY_ALIAS, brokerKeyPair.getPrivate(), DEFAULT_KEYSTORE_PASSWORD, certChain);
        } catch (CertificateException | IOException | KeyStoreException e) {
            //consumer can only throw runtime exception
            throw new RuntimeException("unable to store generated cert", e);
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

    private KeyStore importClientCertsIntoKeyStore(List<String> clientCerts)
        throws IOException, CertificateException, KeyStoreException {
        for (String certPem : clientCerts){
            X509Certificate cert = pemToX509Certificate(certPem);
            brokerKeyStore.setCertificateEntry(BROKER_KEY_ALIAS, cert);
        }
        return brokerKeyStore;
    }

    private static KeyStore loadBrokerKeyStore() throws KeyStoreException {
        // TODO
        throw new KeyStoreException("Not found");
    }
}
