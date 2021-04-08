/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import io.moquette.broker.security.ClientData;
import io.moquette.broker.security.IAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.cert.X509Certificate;

public class CertificateAuthenticator implements IAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthenticator.class);

    @Override
    public boolean checkValid(ClientData clientData) {
        if (!clientData.getCertificateChain().isPresent()) {
            LOG.error("No certificate in client data");
            return false;
        }
        X509Certificate[] certificateChain = clientData.getCertificateChain().get();

        String clientId = clientData.getClientId();
        LOG.info("Client with id {} provided X.509 certificate chain: {}", clientId, certificateChain);
        return isCertificateValid(clientId, certificateChain);
    }

    @SuppressWarnings({"PMD.UnusedFormalParameter", "PMD.UseVarargs"})
    private boolean isCertificateValid(String clientId, X509Certificate[] certificateChain) {
        //TODO: cert validation logic
        return true;
    }
}
