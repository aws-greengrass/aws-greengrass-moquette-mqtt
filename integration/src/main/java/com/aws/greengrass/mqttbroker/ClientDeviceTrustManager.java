/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.ClientDevicesAuthServiceApi;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.net.ssl.X509TrustManager;

public class ClientDeviceTrustManager implements X509TrustManager {
    private static final Logger LOG = LogManager.getLogger(ClientDeviceTrustManager.class);
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    private final ClientDevicesAuthServiceApi clientDevicesAuthService;

    public ClientDeviceTrustManager(ClientDevicesAuthServiceApi clientDevicesAuthService) {
        this.clientDevicesAuthService = clientDevicesAuthService;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        String certPem = x509CertificatesToPem(x509Certificates);
        boolean isAuthenticated = clientDevicesAuthService.verifyClientDeviceIdentity(certPem);
        if (!isAuthenticated) {
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
