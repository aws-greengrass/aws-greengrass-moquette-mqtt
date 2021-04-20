/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.testcommons.testutilities.GGServiceTestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class ClientDeviceTrustManagerTest extends GGServiceTestUtil {
    @Mock
    X509Certificate mockCertificate;

    @Mock
    DeviceAuthClient mockDeviceAuthClient;

    @Test
    void GIVEN_nonEncodableCertificate_WHEN_checkClientTrusted_THEN_CertificateExceptionThrown() throws CertificateEncodingException {
        when(mockCertificate.getEncoded()).thenThrow(new CertificateEncodingException("Couldn't encode certificate"));
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockDeviceAuthClient);
        Assertions.assertThrows(CertificateException.class,
            () -> trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA"));
    }

    @Test
    void GIVEN_encodableCertificate_WHEN_checkClientTrust_THEN_noExceptionThrown() throws CertificateException {
        when(mockCertificate.getEncoded()).thenReturn(new byte[]{0});
        when(mockDeviceAuthClient.createSession(anyString())).thenReturn("session_id");
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockDeviceAuthClient);
        trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA");
    }

    @Test
    void GIVEN_unauthenticatedCertificate_WHEN_checkClientTrust_THEN_CertificateExceptionThrown() throws CertificateEncodingException {
        when(mockCertificate.getEncoded()).thenReturn(new byte[]{0});
        when(mockDeviceAuthClient.createSession(anyString())).thenReturn(null);
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockDeviceAuthClient);
        Assertions.assertThrows(CertificateException.class,
            () -> trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA"));
    }

    @Test
    void GIVEN_singleConnection_WHEN_getSessionForCertificate_THEN_sessionCreatedAndReturned() throws CertificateException {
        when(mockCertificate.getEncoded()).thenReturn(new byte[]{0});
        when(mockDeviceAuthClient.createSession(anyString())).thenReturn("SESSION-ID");
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockDeviceAuthClient);

        // Session should be created when checking if certificate is trusted
        trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA");
        verify(mockDeviceAuthClient, times(1)).createSession(anyString());

        // Session should be retrievable without creating additional session
        reset(mockDeviceAuthClient);
        assertThat(trustManager.getSessionForCertificate(new X509Certificate[]{mockCertificate}), is("SESSION-ID"));
        verify(mockDeviceAuthClient, times(0)).createSession(anyString());
    }

    @Test
    void GIVEN_twoConnectionsWithSameCert_WHEN_getSessionForCertificate_THEN_sessionIsCreatedOnDemand() throws CertificateException {
        when(mockCertificate.getEncoded()).thenReturn(new byte[]{0});
        when(mockDeviceAuthClient.createSession(anyString())).thenReturn("SESSION-ID");

        // Two calls to checkClientTrusted should only result in 1 session being created
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockDeviceAuthClient);
        trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA");
        trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA");
        verify(mockDeviceAuthClient, times(1)).createSession(anyString());

        // Reset mock to return new session ID
        when(mockDeviceAuthClient.createSession(anyString())).thenReturn("SESSION-ID2");

        // A second session should be created after the first is retrieved
        assertThat(trustManager.getSessionForCertificate(new X509Certificate[]{mockCertificate}), is("SESSION-ID"));
        assertThat(trustManager.getSessionForCertificate(new X509Certificate[]{mockCertificate}), is("SESSION-ID2"));
        verify(mockDeviceAuthClient, times(2)).createSession(anyString());
    }

    @Test
    void GIVEN_twoConnectionsWithUniqueCerts_WHEN_checkClientTrusted_THEN_twoSessionsCreated() throws CertificateException {
        X509Certificate mockCertificate2 = Mockito.mock(X509Certificate.class);
        when(mockCertificate.getEncoded()).thenReturn(new byte[]{0});
        when(mockCertificate2.getEncoded()).thenReturn(new byte[]{1});

        // Two connections with different certificates should result in two sessions
        ClientDeviceTrustManager trustManager = new ClientDeviceTrustManager(mockDeviceAuthClient);
        when(mockDeviceAuthClient.createSession(anyString())).thenReturn("SESSION-ID");
        trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate}, "RSA");
        when(mockDeviceAuthClient.createSession(anyString())).thenReturn("SESSION-ID2");
        trustManager.checkClientTrusted(new X509Certificate[]{mockCertificate2}, "RSA");
        verify(mockDeviceAuthClient, times(2)).createSession(anyString());

        assertThat(trustManager.getSessionForCertificate(new X509Certificate[]{mockCertificate}), is("SESSION-ID"));
        assertThat(trustManager.getSessionForCertificate(new X509Certificate[]{mockCertificate2}), is("SESSION-ID2"));
    }
}
