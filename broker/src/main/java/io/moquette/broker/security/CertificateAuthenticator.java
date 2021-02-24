package io.moquette.broker.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.cert.X509Certificate;

public class CertificateAuthenticator implements IAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthenticator.class);

    @Override
    public boolean checkValid(ClientData clientData) {
        String clientId = clientData.getClientId();

        if (!clientData.getCertificate().isPresent()) {
            LOG.info("No certificate in client data");
            return false;
        }
        X509Certificate certificate = clientData.getCertificate().get();

        LOG.info("Client with id {} provided X.509 certificate: {}", clientId, certificate);
        return isCertificateValid(clientId, certificate);
    }

    private boolean isCertificateValid(String clientId, X509Certificate certificate) {
        //TODO: cert validation logic
        return true;
    }
}
