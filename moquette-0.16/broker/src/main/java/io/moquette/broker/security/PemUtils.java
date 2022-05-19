/*
 * Copyright (c) 2022 The original author or authors
 * ------------------------------------------------------
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.moquette.broker.security;

import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

public final class PemUtils {
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    public static String certificatesToPem(Certificate... certificates) throws CertificateEncodingException {
        StringBuilder stringBuilder = new StringBuilder();
        for (Certificate certificate : certificates) {
            stringBuilder.append(certificateToPem(certificate));
            stringBuilder.append(LINE_SEPARATOR);
        }
        return stringBuilder.toString();
    }

    private static String certificateToPem(Certificate certificate) throws CertificateEncodingException {
        // Avoid pulling in a dependency for PEM encoding. X509 certificate are encoded as an ASN.1 DER.
        // A PEM is just a base64 encoding of this, sandwiched between some text anchors
        Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes(StandardCharsets.UTF_8));
        String base64Der = encoder.encodeToString(certificate.getEncoded());
        return String.join(LINE_SEPARATOR, BEGIN_CERT, base64Der, END_CERT);
    }
}
