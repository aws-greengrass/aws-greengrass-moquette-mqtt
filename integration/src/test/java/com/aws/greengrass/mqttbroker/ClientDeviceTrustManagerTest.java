/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.ClientDevicesAuthServiceApi;
import com.aws.greengrass.device.exception.AuthenticationException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.testcommons.testutilities.GGServiceTestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class ClientDeviceTrustManagerTest extends GGServiceTestUtil {
    @Mock
    X509Certificate mockCertificate;

    @Mock
    ClientDevicesAuthServiceApi mockClientDevicesAuthService;

    @Test
    void GIVEN_nonEncodableCertificate_WHEN_checkClientTrusted_THEN_CertificateExceptionThrown() throws Exception {
        when(mockCertificate.getEncoded()).thenThrow(new CertificateEncodingException("Couldn't encode certificate"));
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockClientDevicesAuthService);
        Assertions.assertThrows(CertificateException.class,
            () -> trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA"));
    }

    @Test
    void GIVEN_encodableCertificate_WHEN_checkClientTrust_THEN_noExceptionThrown() throws Exception {
        when(mockCertificate.getEncoded()).thenReturn(new byte[]{0});
        when(mockClientDevicesAuthService.verifyClientDeviceIdentity(anyString())).thenReturn(true);
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockClientDevicesAuthService);
        trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA");
    }

    @Test
    void GIVEN_unauthenticatedCertificate_WHEN_checkClientTrust_THEN_CertificateExceptionThrown() throws Exception {
        when(mockCertificate.getEncoded()).thenReturn(new byte[]{0});
        when(mockClientDevicesAuthService.verifyClientDeviceIdentity(anyString())).thenReturn(false);
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockClientDevicesAuthService);
        Assertions.assertThrows(CertificateException.class,
            () -> trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA"));
    }
}
