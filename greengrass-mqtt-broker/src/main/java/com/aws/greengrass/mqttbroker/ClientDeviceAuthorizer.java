/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import io.moquette.broker.security.ClientData;
import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.security.IAuthorizatorPolicy;
import io.moquette.broker.subscriptions.Topic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

public class ClientDeviceAuthorizer implements IAuthenticator, IAuthorizatorPolicy {
    private static final Logger LOG = LoggerFactory.getLogger(ClientDeviceAuthorizer.class);
    @SuppressWarnings("PMD.UnusedPrivateField")
    private final ClientDeviceTrustManager trustManager;

    public ClientDeviceAuthorizer(ClientDeviceTrustManager trustManager) {
        this.trustManager = trustManager;
    }

    @Override
    public boolean checkValid(ClientData clientData) {
        if (!clientData.getCertificates().isPresent()) {
            LOG.error("No certificate in client data");
            return false;
        }
        X509Certificate[] certificateChain = (X509Certificate[]) clientData.getCertificates().get();

        String clientId = clientData.getClientId();
        LOG.info("Client with id {} provided X.509 certificate chain: {}", clientId, certificateChain);
        return isCertificateValid(clientId, certificateChain);
    }

    @SuppressWarnings({"PMD.UnusedFormalParameter", "PMD.UseVarargs"})
    private boolean isCertificateValid(String clientId, X509Certificate[] certificateChain) {
        //TODO: cert validation logic
        return true;
    }

    @Override
    public boolean canWrite(Topic topic, String s, String s1) {
        return true;
    }

    @Override
    public boolean canRead(Topic topic, String s, String s1) {
        return true;
    }
}
