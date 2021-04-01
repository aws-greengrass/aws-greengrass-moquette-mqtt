package io.moquette.broker.security;

import javax.security.cert.X509Certificate;
import java.util.Optional;

public class ClientData {

    private final String clientId;
    private Optional<String> username = Optional.empty();
    private Optional<X509Certificate[]> certificateChain = Optional.empty();
    private Optional<byte[]> password = Optional.empty();

    public ClientData(String clientId) {
        if (clientId == null) {
            throw new IllegalArgumentException("client id can't be null");
        }
        this.clientId = clientId;
    }

    public void setUsername(String username) {
        this.username = Optional.ofNullable(username);
    }

    public void setCertificateChain(X509Certificate[] certificateChain) {
        this.certificateChain = Optional.ofNullable(certificateChain);
    }

    public void setPassword(byte[] password) {
        this.password = Optional.ofNullable(password);
    }

    public String getClientId() {
        return clientId;
    }

    public Optional<String> getUsername() {
        return username;
    }

    public Optional<byte[]> getPassword() {
        return password;
    }

    public Optional<X509Certificate[]> getCertificateChain() {
        return certificateChain;
    }
}
