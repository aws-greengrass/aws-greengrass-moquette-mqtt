/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt;

import com.aws.greengrass.mqtt.MQTTBrokerKeyStore.EncryptionType;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.aws.greengrass.mqtt.MQTTBrokerKeyStore.BROKER_KEY_ALIAS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class MQTTBrokerKeyStoreTest {
    private static final String IOT_CERT = "-----BEGIN CERTIFICATE-----\n" +
        "MIIDWTCCAkGgAwIBAgIUcMgL9j0BQ6HqadaNuHh/x1WRpd0wDQYJKoZIhvcNAQEL\n" +
        "BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\n" +
        "SW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTIwMDYwNTAxMTY1\n" +
        "OFoXDTQ5MTIzMTIzNTk1OVowHjEcMBoGA1UEAwwTQVdTIElvVCBDZXJ0aWZpY2F0\n" +
        "ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANgiX9P2FVDYjCdSvLdY\n" +
        "H4wpP0IrSpKzfL6FdjzzPx83cZ2EsxmgifhhEOCtbmXrXn8qECd+KtCmbxHXuVnf\n" +
        "rKRp7SEBG+rebZjgyCom3wlffQsns1DZTiL3wMsxJn5CF7qZ3c/kuxNeD7CHk8XR\n" +
        "eJk0anA5Grks8TO5opT75SE4fwvuVyVvi0n54TYM0736Zve+viVs7VfX7zuuFmYr\n" +
        "UVVO07/drT+QD9l+guV57ti0xuLj00utxuL4yf4upKuNQQjWqq6JtL4W/p5l4VZB\n" +
        "ZH/qHAJC7cBLMsovJOYtRTJM9TG0gA7zO6QpN9tOt17kkx24EE0Dyvt2ydcaC/A/\n" +
        "W6ECAwEAAaNgMF4wHwYDVR0jBBgwFoAUY1ds6Gn8cB4AbMFNdkrQJNYXleMwHQYD\n" +
        "VR0OBBYEFMDPfTQjWsyNXxQczxMfhI7JymQIMAwGA1UdEwEB/wQCMAAwDgYDVR0P\n" +
        "AQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBHVKnpobp93Jo1bvg5M4CG3wCq\n" +
        "f40eRErlcZ9XmuYHwzNXjOQCVE14BcuuwefWi1BcCgcjScI7Dxp8PAlL2GtOsl/l\n" +
        "va/XaWoS93bEULTNc8rcm54wnEiQiZf4IaMrljPDwJOOWXQHglpnbfTQCgRE7Mev\n" +
        "7YytSBhlUbgLCEE/IJVbD7aM9vn1t63zqJAnVXsqs5DTvf5+2qBzD0+gkkuSTbVj\n" +
        "67kQAMZs/MBVR2+94Ka5jAPSmotUwJADNQHKD5wB1vLc4vi7TfyDCA/dG0WtDmrx\n" +
        "knISpDCZWWbdcCNFfZVmHGg7F5VBVUCcrB2bz+E9W1PCBYyMCrEJywGxva+w\n" +
        "-----END CERTIFICATE-----\n";

    private static final String DEVICE_CERT_1 = "-----BEGIN CERTIFICATE-----\n" +
        "MIIDWTCCAkGgAwIBAgIUcMgL9j0BQ6HqadaNuHh/x1WRpd0wDQYJKoZIhvcNAQEL\n" +
        "BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\n" +
        "SW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTIwMDYwNTAxMTY1\n" +
        "OFoXDTQ5MTIzMTIzNTk1OVowHjEcMBoGA1UEAwwTQVdTIElvVCBDZXJ0aWZpY2F0\n" +
        "ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANgiX9P2FVDYjCdSvLdY\n" +
        "H4wpP0IrSpKzfL6FdjzzPx83cZ2EsxmgifhhEOCtbmXrXn8qECd+KtCmbxHXuVnf\n" +
        "rKRp7SEBG+rebZjgyCom3wlffQsns1DZTiL3wMsxJn5CF7qZ3c/kuxNeD7CHk8XR\n" +
        "eJk0anA5Grks8TO5opT75SE4fwvuVyVvi0n54TYM0736Zve+viVs7VfX7zuuFmYr\n" +
        "UVVO07/drT+QD9l+guV57ti0xuLj00utxuL4yf4upKuNQQjWqq6JtL4W/p5l4VZB\n" +
        "ZH/qHAJC7cBLMsovJOYtRTJM9TG0gA7zO6QpN9tOt17kkx24EE0Dyvt2ydcaC/A/\n" +
        "W6ECAwEAAaNgMF4wHwYDVR0jBBgwFoAUY1ds6Gn8cB4AbMFNdkrQJNYXleMwHQYD\n" +
        "VR0OBBYEFMDPfTQjWsyNXxQczxMfhI7JymQIMAwGA1UdEwEB/wQCMAAwDgYDVR0P\n" +
        "AQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBHVKnpobp93Jo1bvg5M4CG3wCq\n" +
        "f40eRErlcZ9XmuYHwzNXjOQCVE14BcuuwefWi1BcCgcjScI7Dxp8PAlL2GtOsl/l\n" +
        "va/XaWoS93bEULTNc8rcm54wnEiQiZf4IaMrljPDwJOOWXQHglpnbfTQCgRE7Mev\n" +
        "7YytSBhlUbgLCEE/IJVbD7aM9vn1t63zqJAnVXsqs5DTvf5+2qBzD0+gkkuSTbVj\n" +
        "67kQAMZs/MBVR2+94Ka5jAPSmotUwJADNQHKD5wB1vLc4vi7TfyDCA/dG0WtDmrx\n" +
        "knISpDCZWWbdcCNFfZVmHGg7F5VBVUCcrB2bz+E9W1PCBYyMCrEJywGxfb+w\n" +
        "-----END CERTIFICATE-----\n";

    private static final String DEVICE_CERT_2 = "-----BEGIN CERTIFICATE-----\n" +
        "MIIDWTCCAkGgAwIBAgIUcMgL9j0BQ6HqadaNuHh/x1WRpd0wDQYJKoZIhvcNAQEL\n" +
        "BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\n" +
        "SW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTIwMDYwNTAxMTY1\n" +
        "OFoXDTQ5MTIzMTIzNTk1OVowHjEcMBoGA1UEAwwTQVdTIElvVCBDZXJ0aWZpY2F0\n" +
        "ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANgiX9P2FVDYjCdSvLdY\n" +
        "H4wpP0IrSpKzfL6FdjzzPx83cZ2EsxmgifhhEOCtbmXrXn8qECd+KtCmbxHXuVnf\n" +
        "rKRp7SEBG+rebZjgyCom3wlffQsns1DZTiL3wMsxJn5CF7qZ3c/kuxNeD7CHk8XR\n" +
        "eJk0anA5Grks8TO5opT75SE4fwvuVyVvi0n54TYM0736Zve+viVs7VfX7zuuFmYr\n" +
        "UVVO07/drT+QD9l+guV57ti0xuLj00utxuL4yf4upKuNQQjWqq6JtL4W/p5l4VZB\n" +
        "ZH/qHAJC7cBLMsovJOYtRTJM9TG0gA7zO6QpN9tOt17kkx24EE0Dyvt2ydcaC/A/\n" +
        "W6ECAwEAAaNgMF4wHwYDVR0jBBgwFoAUY1ds6Gn8cB4AbMFNdkrQJNYXleMwHQYD\n" +
        "VR0OBBYEFMDPfTQjWsyNXxQczxMfhI7JymQIMAwGA1UdEwEB/wQCMAAwDgYDVR0P\n" +
        "AQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBHVKnpobp93Jo1bvg5M4CG3wCq\n" +
        "f40eRErlcZ9XmuYHwzNXjOQCVE14BcuuwefWi1BcCgcjScI7Dxp8PAlL2GtOsl/l\n" +
        "va/XaWoS93bEULTNc8rcm54wnEiQiZf4IaMrljPDwJOOWXQHglpnbfTQCgRE7Mev\n" +
        "7YytSBhlUbgLCEE/IJVbD7aM9vn1t63zqJAnVXsqs5DTvf5+2qBzD0+gkkuSTbVj\n" +
        "67kQAMZs/MBVR2+94Ka5jAPSmotUwJADNQHKD5wB1vLc4vi7TfyDCA/dG0WtDmrx\n" +
        "knISpDCZWWbdcCNFfZVmHGg7F5VBVUCcrB2bz+E9W1PCBYyMCrEJywGxrt+w\n" +
        "-----END CERTIFICATE-----\n";

    private static final String BEGIN_CSR = "-----BEGIN CERTIFICATE REQUEST-----";
    private static final String END_CSR = "-----END CERTIFICATE REQUEST-----";

    @TempDir
    Path rootDir;

    private MQTTBrokerKeyStore mqttBrokerKeyStore;

    @BeforeEach
    public void setup() {
        mqttBrokerKeyStore = new MQTTBrokerKeyStore(rootDir);
    }

    @Test
    void GIVEN_root_dir_WHEN_MQTTBrokerKeyStore_created_THEN_keystore_path_and_password_initialized() {
        Assertions.assertNotEquals("", mqttBrokerKeyStore.getJksPassword(),
            "keystore password should not be empty");
        Assertions.assertEquals(rootDir.resolve("keystore.jks").toString(), mqttBrokerKeyStore.getJksPath(),
            "keystore should be created in the root dir");
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getCsr_called_with_RSA_THEN_valid_keypair_and_csr_generated() throws Exception {
        String csr = mqttBrokerKeyStore.getCsr(EncryptionType.RSA);
        assertThat(mqttBrokerKeyStore.getBrokerKeyPair().getPrivate().getAlgorithm(), is("RSA"));
        assertThat(csr, containsString(BEGIN_CSR));
        assertThat(csr, containsString(END_CSR));
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getCsr_called_with_EC_THEN_valid_keypair_and_csr_generated() throws Exception {
        String csr = mqttBrokerKeyStore.getCsr(EncryptionType.EC);
        assertThat(mqttBrokerKeyStore.getBrokerKeyPair().getPrivate().getAlgorithm(), is("EC"));
        assertThat(csr, containsString(BEGIN_CSR));
        assertThat(csr, containsString(END_CSR));
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_updateServerCertificate_called_THEN_success() throws Exception {
        mqttBrokerKeyStore.initialize();
        mqttBrokerKeyStore.getCsr(EncryptionType.RSA);
        X509Certificate testServerCert = pemToX509Certificate(IOT_CERT);
        mqttBrokerKeyStore.updateServerCertificate(testServerCert);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = mqttBrokerKeyStore.getJksPassword();
        String jksPath = mqttBrokerKeyStore.getJksPath();
        char[] passwd = password.toCharArray();
        try (FileInputStream is = new FileInputStream(jksPath)) {
            keystore.load(is, passwd);
        }
        assertThat(keystore.getCertificate(BROKER_KEY_ALIAS), is(pemToX509Certificate(IOT_CERT)));
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_updateCertificates_called_THEN_success() throws Exception {
        Map<String, String> testDeviceCerts = new HashMap<>();
        testDeviceCerts.put("device1", DEVICE_CERT_1);
        List<String> testCaCerts = new ArrayList<>();
        testCaCerts.add(IOT_CERT);

        mqttBrokerKeyStore.initialize();
        mqttBrokerKeyStore.updateCertificates(testDeviceCerts, testCaCerts);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = mqttBrokerKeyStore.getJksPassword();
        String jksPath = mqttBrokerKeyStore.getJksPath();
        char[] passwd = password.toCharArray();
        try (FileInputStream is = new FileInputStream(jksPath)) {
            keystore.load(is, passwd);
        }
        assertThat(keystore.getCertificate("device1"), is(pemToX509Certificate(DEVICE_CERT_1)));
        assertThat(keystore.getCertificate("CA0"), is(pemToX509Certificate(IOT_CERT)));

        // update device certs
        testDeviceCerts.remove("device1");
        testDeviceCerts.put("device2", DEVICE_CERT_2);
        mqttBrokerKeyStore.updateCertificates(testDeviceCerts, testCaCerts);
        try (FileInputStream is = new FileInputStream(jksPath)) {
            keystore.load(is, passwd);
        }
        assertThat(keystore.getCertificate("device2"), is(pemToX509Certificate(DEVICE_CERT_2)));
        assertFalse(keystore.containsAlias("device1"));
        assertThat(keystore.getCertificate("CA0"), is(pemToX509Certificate(IOT_CERT)));
    }

    private X509Certificate pemToX509Certificate(String certPem) throws IOException, CertificateException {
        byte[] certBytes = certPem.getBytes(StandardCharsets.UTF_8);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (InputStream certStream = new ByteArrayInputStream(certBytes)) {
            cert = (X509Certificate) certFactory.generateCertificate(certStream);
        }
        return cert;
    }
}
