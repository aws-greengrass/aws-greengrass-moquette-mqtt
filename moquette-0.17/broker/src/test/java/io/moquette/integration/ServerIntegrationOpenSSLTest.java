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

package io.moquette.integration;

import java.io.IOException;
import java.util.Properties;

import io.moquette.broker.Server;
import io.moquette.broker.config.IConfig;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslProvider;
import org.junit.jupiter.api.BeforeAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Check that Moquette could also handle SSL with OpenSSL provider.
 */
public class ServerIntegrationOpenSSLTest extends ServerIntegrationSSLTest {

    private static final Logger LOG = LoggerFactory.getLogger(ServerIntegrationOpenSSLTest.class);

    @BeforeAll
    public static void beforeTests() {
        LOG.info("try to initialize OpenSSL native library");
        OpenSsl.ensureAvailability();
        LOG.info("OpenSSL initialized");
    }

    @Override
    protected void startServer() throws IOException {
        String file = getClass().getResource("/").getPath();
        System.setProperty("moquette.path", file);
        m_server = new Server();
        Properties sslProps = new Properties();

        sslProps.put(IConfig.SSL_PROVIDER, SslProvider.OPENSSL.name());
//        sslProps.put(BrokerConstants.NEED_CLIENT_AUTH, "true");

        sslProps.put(IConfig.SSL_PORT_PROPERTY_NAME, "8883");
        sslProps.put(IConfig.JKS_PATH_PROPERTY_NAME, "src/test/resources/serverkeystore.jks");
        sslProps.put(IConfig.KEY_STORE_PASSWORD_PROPERTY_NAME, "passw0rdsrv");
        sslProps.put(IConfig.KEY_MANAGER_PASSWORD_PROPERTY_NAME, "passw0rdsrv");
        sslProps.put(IConfig.DATA_PATH_PROPERTY_NAME, dbPath);
        sslProps.put(IConfig.PERSISTENCE_ENABLED_PROPERTY_NAME, "true");
        sslProps.put(IConfig.PERSISTENT_QUEUE_TYPE_PROPERTY_NAME, "h2");

        sslProps.put(IConfig.ENABLE_TELEMETRY_NAME, "false");
        m_server.startServer(sslProps);
    }
}
