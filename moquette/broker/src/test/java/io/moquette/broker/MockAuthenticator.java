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

package io.moquette.broker;

import java.util.Map;
import java.util.Set;

import io.moquette.broker.security.ClientData;
import io.moquette.broker.security.IAuthenticator;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Test utility to implements authenticator instance.
 */
public class MockAuthenticator implements IAuthenticator {

    private Set<String> m_clientIds;
    private Map<String, String> m_userPwds;

    public MockAuthenticator(Set<String> clientIds, Map<String, String> userPwds) {
        m_clientIds = clientIds;
        m_userPwds = userPwds;
    }

    @Override
    public boolean checkValid(ClientData clientData) {
        if (!m_clientIds.contains(clientData.getClientId())) {
            return false;
        }
        if (!clientData.getUsername().isPresent()) {
            return false;
        }
        String username = clientData.getUsername().get();
        if (!m_userPwds.containsKey(username)) {
            return false;
        }
        if (!clientData.getPassword().isPresent()) {
            return false;
        }
        byte[] password = clientData.getPassword().get();
        return m_userPwds.get(username).equals(new String(password, UTF_8));
    }

}
