/*
 * Copyright (c) 2012-2018 The original author or authors
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
