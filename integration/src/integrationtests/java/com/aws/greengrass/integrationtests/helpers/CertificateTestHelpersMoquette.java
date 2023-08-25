/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.integrationtests.helpers;

import com.aws.greengrass.clientdevices.auth.certificate.CertificateStore;
import com.aws.greengrass.util.EncryptionUtils;
import com.aws.greengrass.util.Pair;
import com.aws.greengrass.util.Utils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import software.amazon.awssdk.utils.ImmutableMap;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;


public final class CertificateTestHelpersMoquette {
    private static final int DEFAULT_TEST_CA_DURATION_SECONDS = 3600;
    public static final String KEY_TYPE_RSA = "RSA";
    public static final String RSA_SIGNING_ALGORITHM = "SHA256withRSA";
    public static final String KEY_TYPE_EC = "EC";
    public static final String ECDSA_SIGNING_ALGORITHM = "SHA256withECDSA";
    public static final ImmutableMap<String, String> CERTIFICATE_SIGNING_ALGORITHM =
            ImmutableMap.of(KEY_TYPE_RSA, RSA_SIGNING_ALGORITHM, KEY_TYPE_EC, ECDSA_SIGNING_ALGORITHM);

    private CertificateTestHelpersMoquette() {
    }

    static {
        // If not added "BC" is not recognized as the security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    private enum CertificateTypes {
        ROOT_CA, INTERMEDIATE_CA, SERVER_CERTIFICATE, CLIENT_CERTIFICATE
    }

    public static X509Certificate createRootCertificateAuthority(String commonName, KeyPair kp)
            throws CertificateException, OperatorCreationException, CertIOException, NoSuchAlgorithmException {
        return createCertificate(null, commonName, kp.getPublic(), kp.getPrivate(), CertificateTypes.ROOT_CA);
    }

    public static X509Certificate createIntermediateCertificateAuthority(X509Certificate caCert, String commonName,
                                                                         PublicKey publicKey, PrivateKey caPrivateKey)
            throws NoSuchAlgorithmException, CertificateException, CertIOException, OperatorCreationException {
        return createCertificate(caCert, commonName, publicKey, caPrivateKey, CertificateTypes.INTERMEDIATE_CA);
    }

    public static X509Certificate createServerCertificate(X509Certificate caCert, String commonName,
                                                          PublicKey publicKey, PrivateKey caPrivateKey)
            throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
        return createCertificate(caCert, commonName, publicKey, caPrivateKey, CertificateTypes.SERVER_CERTIFICATE);
    }

    public static X509Certificate createClientCertificate(X509Certificate caCert, String commonName,
                                                          PublicKey publicKey, PrivateKey caPrivateKey)
            throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, CertIOException {
        return createCertificate(caCert, commonName, publicKey, caPrivateKey, CertificateTypes.CLIENT_CERTIFICATE);
    }

    private static X509Certificate createCertificate(X509Certificate caCert, String commonName, PublicKey publicKey,
                                                     PrivateKey caPrivateKey, CertificateTypes type)
            throws NoSuchAlgorithmException, CertIOException, CertificateException, OperatorCreationException {
        Pair<Date, Date> dateRange = getValidityDateRange();
        X500Name subject = getX500Name(commonName);

        X509v3CertificateBuilder builder;
        if (type == CertificateTypes.ROOT_CA) {
            builder = new JcaX509v3CertificateBuilder(subject, getSerialNumber(), dateRange.getLeft(),
                    dateRange.getRight(), subject, publicKey);
        } else {
            builder = new JcaX509v3CertificateBuilder(caCert, getSerialNumber(), dateRange.getLeft(),
                    dateRange.getRight(), subject, publicKey);
        }

        buildCertificateExtensions(builder, caCert, publicKey, type);
        X509CertificateHolder certHolder = signCertificate(builder, caPrivateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    private static X509CertificateHolder signCertificate(X509v3CertificateBuilder certBuilder, PrivateKey privateKey)
            throws OperatorCreationException {
        String signingAlgorithm = CERTIFICATE_SIGNING_ALGORITHM.get(privateKey.getAlgorithm());
        final ContentSigner contentSigner =
                new JcaContentSignerBuilder(signingAlgorithm).setProvider("BC").build(privateKey);

        return certBuilder.build(contentSigner);
    }

    private static void buildCertificateExtensions(X509v3CertificateBuilder builder, X509Certificate caCert,
                                                   PublicKey publicKey, CertificateTypes type)
            throws NoSuchAlgorithmException, CertificateEncodingException, CertIOException {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));

        if (type == CertificateTypes.ROOT_CA) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                            extUtils.createAuthorityKeyIdentifier(publicKey))
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }

        if (type == CertificateTypes.INTERMEDIATE_CA) {
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                    .addExtension(Extension.keyUsage, true, new X509KeyUsage(
                            X509KeyUsage.digitalSignature | X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign));
        }

        if (type == CertificateTypes.SERVER_CERTIFICATE) {
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.extendedKeyUsage, true,
                            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        }

        if (type == CertificateTypes.CLIENT_CERTIFICATE) {
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.extendedKeyUsage, true,
                            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        }
    }

    private static BigInteger getSerialNumber() {
        return new BigInteger(160, new SecureRandom());
    }

    private static Pair<Date, Date> getValidityDateRange() {
        Instant now = Instant.now();
        // TODO: caller should pass a clock or date range in instead
        Date notBefore = Date.from(now.minusSeconds(1));
        Date notAfter = Date.from(now.plusSeconds(DEFAULT_TEST_CA_DURATION_SECONDS));
        return new Pair(notBefore, notAfter);
    }

    private static X500Name getX500Name(String commonName) {
        X500NameBuilder nameBuilder = new X500NameBuilder(X500Name.getDefaultStyle());
        nameBuilder.addRDN(BCStyle.C, "US");
        nameBuilder.addRDN(BCStyle.O, "Internet Widgits Pty Ltd");
        nameBuilder.addRDN(BCStyle.OU, "Amazon Web Services");
        nameBuilder.addRDN(BCStyle.ST, "Washington");
        nameBuilder.addRDN(BCStyle.L, "Seattle");
        nameBuilder.addRDN(BCStyle.CN, commonName);

        return nameBuilder.build();
    }


    /**
     * Verifies if one certificate was signed by another.
     *
     * @param issuerCA    X509Certificate issuer cert
     * @param certificate X509Certificate signed cert
     */
    public static boolean wasCertificateIssuedBy(X509Certificate issuerCA, X509Certificate certificate)
            throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> leafCertificate = Arrays.asList(certificate);
        CertPath leafCertPath = cf.generateCertPath(leafCertificate);

        try {
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            TrustAnchor trustAnchor = new TrustAnchor(issuerCA, null);
            PKIXParameters validationParams = new PKIXParameters(new HashSet<>(Collections.singletonList(trustAnchor)));
            validationParams.setRevocationEnabled(false);
            cpv.validate(leafCertPath, validationParams);
            return true;
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            return false;
        }
    }

    public static List<X509Certificate> createClientCertificates(int amount) throws Exception {
        KeyPair rootKeyPair = CertificateStore.newRSAKeyPair(2048);
        X509Certificate rootCA = CertificateTestHelpersMoquette.createRootCertificateAuthority("root", rootKeyPair);

        List<X509Certificate> clientCertificates = new ArrayList<>();

        for (int i = 0; i < amount; i++) {
            KeyPair clientKeyPair = CertificateStore.newRSAKeyPair(2048);

            clientCertificates.add(createClientCertificate(rootCA, "AWS IoT Certificate", clientKeyPair.getPublic(),
                    rootKeyPair.getPrivate()));
        }

        return clientCertificates;
    }

    public static List<X509Certificate> loadX509Certificate(String pem) throws IOException, CertificateException {

        try (InputStream targetStream = IOUtils.toInputStream(pem)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");

            return new ArrayList<>((Collection<? extends X509Certificate>) factory.generateCertificates(targetStream));
        }
    }

    @SuppressWarnings("PMD.AvoidFileStream")
    public static void writeToPath(Path filePath, String boundary, List<byte[]> encodings) throws IOException {
        File file = filePath.toFile();

        if (!Files.exists(filePath)) {
            Utils.createPaths(filePath.getParent());
        }

        try (FileWriter fw = new FileWriter(file, true)) {
            for (byte[] encoding : encodings) {
                fw.write(EncryptionUtils.encodeToPem(boundary, encoding));
            }
        }
    }
}
