/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.device.exception.AuthenticationException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.X509TrustManager;

public class ClientDeviceTrustManager implements X509TrustManager {
    private static final Logger LOG = LogManager.getLogger(ClientDeviceTrustManager.class);
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private static final String CERTIFICATE_PEM = "certificatePem";
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
            LOG.atError("Unable to authenticate client device");
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
    public String getSessionForCertificate(X509Certificate... x509Certificates) {
        String certPem = null;

        try {
            certPem = x509CertificatesToPem(x509Certificates);
        } catch (CertificateEncodingException e) {
            LOG.atError().cause(e).log("Unable to PEM encode X.509 certificate");
            return null;
        }

        String sessionId = sessionMap.remove(certPem);
        if (sessionId == null) {
            sessionId = createSession(certPem);
        }
        return sessionId;
    }

    private String createSession(String certPem) {
        try {
            return deviceAuthClient.createSession(certPem);
        } catch (AuthenticationException e) {
            LOG.atError().cause(e).kv(CERTIFICATE_PEM, certPem).log("Can't authenticate certificate");
            return null;
        }
    }

    private static String x509CertificatesToPem(X509Certificate... x509Certificates)
        throws CertificateEncodingException {
        StringBuilder stringBuilder = new StringBuilder();
        for (X509Certificate certificate : x509Certificates) {
            stringBuilder.append(x509CertificateToPem(certificate));
            stringBuilder.append(LINE_SEPARATOR);
        }
        return stringBuilder.toString();
    }

    private static String x509CertificateToPem(X509Certificate x509Certificate) throws CertificateEncodingException {
        // Avoid pulling in a dependency for PEM encoding. X509 certificate are encoded as an ASN.1 DER.
        // A PEM is just a base64 encoding of this, sandwiched between some text anchors
        Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes(StandardCharsets.UTF_8));
        String base64Der = encoder.encodeToString(x509Certificate.getEncoded());
        return String.join(LINE_SEPARATOR, BEGIN_CERT, base64Der, END_CERT);
    }
}
