/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.DeviceAuthClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.X509TrustManager;

public class ClientDeviceTrustManager implements X509TrustManager {
    private static final Logger LOG = LoggerFactory.getLogger(ClientDeviceTrustManager.class);
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    private final DeviceAuthClient deviceAuthClient;
    private final Map<String, String> sessionMap;

    public ClientDeviceTrustManager(DeviceAuthClient deviceAuthClient) {
        this.deviceAuthClient = deviceAuthClient;
        this.sessionMap = new ConcurrentHashMap<>();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        String certPem = x509CertificatesToPem(x509Certificates);
        String sessionId = sessionMap.computeIfAbsent(certPem, k -> createSession(certPem));
        if (sessionId == null) {
            LOG.error("Unable to authenticate client device");
            throw new CertificateException("Unable to authenticate client device");
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        throw new CertificateException("Unsupported operation");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /**
     * Returns a valid session ID for the given certificate chain, if it exists.
     *
     * @param x509Certificates certificate chain
     * @return a session id
     */
    @SuppressWarnings("PMD.UseVarargs")
    public String getSessionForCertificate(X509Certificate[] x509Certificates) {
        String certPem = null;

        try {
            certPem = x509CertificatesToPem(x509Certificates);
        } catch (CertificateEncodingException e) {
            LOG.error("Unable to PEM encode x509Certificate");
            return null;
        }

        String sessionId = sessionMap.remove(certPem);
        if (sessionId == null) {
            sessionId = createSession(certPem);
        }
        return sessionId;
    }

    private String createSession(String certPem) {
        return deviceAuthClient.createSession(certPem);
    }

    @SuppressWarnings("PMD.UseVarargs")
    private static String x509CertificatesToPem(X509Certificate[] x509Certificates)
        throws CertificateEncodingException {
        if (x509Certificates.length > 1) {
            // TODO: Support cert chains
            LOG.error("Certificate chains are unsupported");
            return "";
        }

        return x509CertificateToPem(x509Certificates[0]);
    }

    private static String x509CertificateToPem(X509Certificate x509Certificate) throws CertificateEncodingException {
        // Avoid pulling in a dependency for PEM encoding. X509 certificate are encoded as an ASN.1 DER.
        // A PEM is just a base64 encoding of this, sandwiched between some text anchors
        Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes(StandardCharsets.UTF_8));
        String base64Der = encoder.encodeToString(x509Certificate.getEncoded());
        return String.join(LINE_SEPARATOR, BEGIN_CERT, base64Der, END_CERT);
    }
}
