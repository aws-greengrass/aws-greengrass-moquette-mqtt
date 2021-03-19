package io.moquette.broker.security;

import lombok.Getter;
import lombok.NonNull;

import javax.security.cert.X509Certificate;
import java.util.Optional;

@Getter
public class ClientData {

    @NonNull private final String clientId;
    private Optional<String> username = Optional.empty();
    private Optional<X509Certificate[]> certificateChain = Optional.empty();
    private Optional<byte[]> password = Optional.empty();

    public ClientData(String clientId) {
        this.clientId = clientId;
    }

    public void setUsername(String username) {
        this.username = Optional.ofNullable(username);
    }

    public void setCertificate(X509Certificate[] certificateChain) {
        this.certificateChain = Optional.ofNullable(certificateChain);
    }

    public void setPassword(byte[] password) {
        this.password = Optional.ofNullable(password);
    }
}
