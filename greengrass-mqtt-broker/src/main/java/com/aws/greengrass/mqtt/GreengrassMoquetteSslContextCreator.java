package com.aws.greengrass.mqtt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Objects;

import io.moquette.BrokerConstants;
import io.moquette.broker.ISslContextCreator;
import io.moquette.broker.config.IConfig;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GreengrassMoquetteSslContextCreator implements ISslContextCreator {
    private static final Logger LOG = LoggerFactory.getLogger(GreengrassMoquetteSslContextCreator.class);

    private final IConfig props;

    private final TrustManager trustManager;

    GreengrassMoquetteSslContextCreator(IConfig props) {
        this(props, null);
    }

    public GreengrassMoquetteSslContextCreator(IConfig props, TrustManager trustManager) {
        this.props = Objects.requireNonNull(props);
        this.trustManager = trustManager;
    }

    @Override
    public SslContext initSSLContext() {
        LOG.info("Checking SSL configuration properties...");

        final String keyPassword = props.getProperty(BrokerConstants.KEY_MANAGER_PASSWORD_PROPERTY_NAME);
        if (keyPassword == null || keyPassword.isEmpty()) {
            LOG.warn("The key manager password is null or empty. The SSL context won't be initialized.");
            return null;
        }

        try {
            SslProvider sslProvider = getSSLProvider();
            KeyStore ks = loadKeyStore();
            SslContextBuilder contextBuilder;
            switch (sslProvider) {
                case JDK:
                    contextBuilder = builderWithJdkProvider(ks, keyPassword);
                    break;
                case OPENSSL:
                case OPENSSL_REFCNT:
                    contextBuilder = builderWithOpenSSLProvider(ks, keyPassword);
                    break;
                default:
                    LOG.error("unsupported SSL provider {}", sslProvider);
                    return null;
            }
            // if client authentification is enabled a trustmanager needs to be added to the ServerContext
            String sNeedsClientAuth = props.getProperty(BrokerConstants.NEED_CLIENT_AUTH, "false");
            if (Boolean.valueOf(sNeedsClientAuth)) {
                addClientAuthentication(ks, contextBuilder);
            }
            contextBuilder.sslProvider(sslProvider);
            SslContext sslContext = contextBuilder.build();
            LOG.info("The SSL context has been initialized successfully.");
            return sslContext;
        } catch (GeneralSecurityException | IOException ex) {
            LOG.error("Unable to initialize SSL context.", ex);
            return null;
        }
    }

    private KeyStore loadKeyStore() throws IOException, GeneralSecurityException {
        final String jksPath = props.getProperty(BrokerConstants.JKS_PATH_PROPERTY_NAME);
        LOG.info("Initializing SSL context. KeystorePath = {}.", jksPath);
        if (jksPath == null || jksPath.isEmpty()) {
            LOG.warn("The keystore path is null or empty. The SSL context won't be initialized.");
            return null;
        }
        final String keyStorePassword = props.getProperty(BrokerConstants.KEY_STORE_PASSWORD_PROPERTY_NAME);
        if (keyStorePassword == null || keyStorePassword.isEmpty()) {
            LOG.warn("The keystore password is null or empty. The SSL context won't be initialized.");
            return null;
        }
        String ksType = props.getProperty(BrokerConstants.KEY_STORE_TYPE, "jks");
        final KeyStore keyStore = KeyStore.getInstance(ksType);
        LOG.info("Loading keystore. KeystorePath = {}.", jksPath);
        try (InputStream jksInputStream = jksDatastore(jksPath)) {
            keyStore.load(jksInputStream, keyStorePassword.toCharArray());
        }
        return keyStore;
    }

    private static SslContextBuilder builderWithJdkProvider(KeyStore ks, String keyPassword)
        throws GeneralSecurityException {
        LOG.info("Initializing key manager...");
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyPassword.toCharArray());
        LOG.info("Initializing SSL context...");
        return SslContextBuilder.forServer(kmf);
    }

    /**
     * The OpenSSL provider does not support the {@link KeyManagerFactory}, so we have to lookup the integration
     * certificate and key in order to provide it to OpenSSL.
     * <p>
     * TODO: SNI is currently not supported, we use only the first found private key.
     */
    private static SslContextBuilder builderWithOpenSSLProvider(KeyStore ks, String keyPassword)
        throws GeneralSecurityException {
        for (String alias : Collections.list(ks.aliases())) {
            if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                PrivateKey key = (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
                Certificate[] chain = ks.getCertificateChain(alias);
                X509Certificate[] certChain = new X509Certificate[chain.length];
                System.arraycopy(chain, 0, certChain, 0, chain.length);
                return SslContextBuilder.forServer(key, certChain);
            }
        }
        throw new KeyManagementException("the SSL key-store does not contain a private key");
    }

    private void addClientAuthentication(KeyStore ks, SslContextBuilder contextBuilder)
        throws NoSuchAlgorithmException, KeyStoreException {
        contextBuilder.clientAuth(ClientAuth.REQUIRE);
        if (trustManager != null) {
            contextBuilder.trustManager(trustManager);
        } else {
            LOG.warn("No trust manager present. The keystore will be used as a truststore.");
            // use keystore as truststore, as integration needs to trust certificates signed by the integration certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            contextBuilder.trustManager(tmf);
        }
    }

    private SslProvider getSSLProvider() {
        String providerName = props.getProperty(BrokerConstants.SSL_PROVIDER, SslProvider.JDK.name());
        try {
            return SslProvider.valueOf(providerName);
        } catch (IllegalArgumentException e) {
            LOG.warn("unknown SSL Provider {}, falling back on JDK provider", providerName);
            return SslProvider.JDK;
        }
    }

    private InputStream jksDatastore(String jksPath) throws FileNotFoundException {
        URL jksUrl = getClass().getClassLoader().getResource(jksPath);
        if (jksUrl != null) {
            LOG.info("Starting with jks at {}, jks normal {}", jksUrl.toExternalForm(), jksUrl);
            return getClass().getClassLoader().getResourceAsStream(jksPath);
        }
        LOG.warn("No keystore has been found in the bundled resources. Scanning filesystem...");
        File jksFile = new File(jksPath);
        if (jksFile.exists()) {
            LOG.info("Loading external keystore. Url = {}.", jksFile.getAbsolutePath());
            return new FileInputStream(jksFile);
        }
        throw new FileNotFoundException("The keystore file does not exist. Url = " + jksFile.getAbsolutePath());
    }
}
