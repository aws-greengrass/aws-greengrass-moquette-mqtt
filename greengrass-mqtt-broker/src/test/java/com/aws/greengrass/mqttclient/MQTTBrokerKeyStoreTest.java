/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttclient;

import com.aws.greengrass.mqtt.MQTTBrokerKeyStore;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;

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

    @TempDir
    Path rootDir;

    private MQTTBrokerKeyStore mqttBrokerKeyStore;

    @BeforeEach
    public void setup() {
        mqttBrokerKeyStore = new MQTTBrokerKeyStore(rootDir);
    }

    @Test
    void GIVEN_MQTTBrokerKeyStore_WHEN_getKeyStore_called_THEN_basic_keystore_generated() {
        Assertions.assertNotEquals("", mqttBrokerKeyStore.getJksPassword(),
            "keystore password should not be empty");
        Assertions.assertEquals(rootDir.resolve("keystore.jks").toString(), mqttBrokerKeyStore.getJksPath(),
            "keystore should be created in the root dir");
    }

    // TODO: increase test coverage!
}
