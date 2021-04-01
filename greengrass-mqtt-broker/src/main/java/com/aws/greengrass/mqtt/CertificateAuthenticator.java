package com.aws.greengrass.mqtt;

import io.moquette.broker.security.ClientData;
import io.moquette.broker.security.IAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.cert.X509Certificate;

public class CertificateAuthenticator implements IAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthenticator.class);

    @Override
    public boolean checkValid(ClientData clientData) {
        String clientId = clientData.getClientId();

        if (!clientData.getCertificateChain().isPresent()) {
            LOG.error("No certificate in client data");
            return false;
        }
        X509Certificate[] certificateChain = clientData.getCertificateChain().get();

        LOG.info("Client with id {} provided X.509 certificate chain: {}", clientId, certificateChain);
        return isCertificateValid(clientId, certificateChain);
    }

    private boolean isCertificateValid(String clientId, X509Certificate[] certificateChain) {
        //TODO: cert validation logic
        return true;
    }
}
