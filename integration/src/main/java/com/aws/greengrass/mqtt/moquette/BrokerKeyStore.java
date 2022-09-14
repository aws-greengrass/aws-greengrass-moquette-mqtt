/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette;

import com.aws.greengrass.clientdevices.auth.api.CertificateUpdateEvent;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.util.Utils;
import lombok.Getter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

public class BrokerKeyStore {
    private static final Logger LOGGER = LogManager.getLogger(BrokerKeyStore.class);
    private static final String KEYSTORE_FILE_NAME = "keystore.jks";
    private static final String BROKER_KEY_ALIAS = "pk";

    private final Path rootPath;
    @Getter
    private final String jksPath;
    @Getter
    private final String jksPassword;
    private KeyStore jks;

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
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, jksPassword.toCharArray());
            jks = ks;
            commit();
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("Unable to load broker keystore", e);
        }
    }

    /**
     * Update KeyStore key certificate.
     *
     * @param certificateUpdate Updated certificate
     * @throws KeyStoreException If unable to set key entry.
     */
    public void updateServerCertificate(CertificateUpdateEvent certificateUpdate) throws KeyStoreException {
        X509Certificate[] fullChain = Stream.concat(Stream.of(certificateUpdate.getCertificate()),
                Stream.of(certificateUpdate.getCaCertificates()))
            .toArray(X509Certificate[]::new);

        jks.setKeyEntry(BROKER_KEY_ALIAS, certificateUpdate.getKeyPair().getPrivate(),
            jksPassword.toCharArray(), fullChain);

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
