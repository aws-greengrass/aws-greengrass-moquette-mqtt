/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.iot.evergreen.mqtt.broker;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import lombok.AccessLevel;
import lombok.Getter;

public class MQTTBrokerKeyStore {

    private static final int RSA_KEY_LENGTH = 2048;
    private static final String RSA_KEY_INSTANCE = "RSA";
    public static final String DEFAULT_KEYSTORE_PASSWORD_STRING = "";
    public static final char[] DEFAULT_KEYSTORE_PASSWORD = DEFAULT_KEYSTORE_PASSWORD_STRING.toCharArray();

    @Getter(AccessLevel.PACKAGE)
    private static KeyStore brokerKeyStore;
    private static KeyPair brokerKeyPair;

    // getter
    public static KeyPair getBrokerKeyPair() {
        return brokerKeyPair;
    }

    /**
     *
     * @return broker key store
     * @throws KeyStoreException exception in creating key store
     */
    public KeyStore getKeyStore() throws KeyStoreException {
        try {
            brokerKeyStore = loadBrokerKeyStore();
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            brokerKeyStore = createDefaultBrokerKeyStore();
        }
        return brokerKeyStore;
    }

    /**
     *
     * @param keyStore keystore to write to disk
     * @throws IOException if there was an I/O problem with data
     * @throws CertificateException  if any of the certificates included in the keystore data could not be stored
     * @throws NoSuchAlgorithmException if the appropriate data integrity algorithm could not be found
     * @throws KeyStoreException  if the keystore has not been initialized (loaded)
     */
    public void writeKeyStoreToDisk(KeyStore keyStore) throws
        IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        try (FileOutputStream outputStream = new FileOutputStream(getBrokerKeyStorePath())) {
            keyStore.store(outputStream, DEFAULT_KEYSTORE_PASSWORD);
        }
    }

    /**
     *
     * @return path to broker key store
     */
    public String getBrokerKeyStorePath() {
        return "work/" + MQTTService.SERVICE_NAME + "/serverstore.jks";
    }

    private KeyStore loadBrokerKeyStore() throws
        KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream is = new FileInputStream(getBrokerKeyStorePath())) {
            keystore.load(is, DEFAULT_KEYSTORE_PASSWORD);
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
            ks.load(null, DEFAULT_KEYSTORE_PASSWORD);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("unable to load broker keystore", e);
        }
        return ks;
    }

    private static KeyPair newRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_KEY_INSTANCE);
        kpg.initialize(RSA_KEY_LENGTH);
        return kpg.generateKeyPair();
    }
}
