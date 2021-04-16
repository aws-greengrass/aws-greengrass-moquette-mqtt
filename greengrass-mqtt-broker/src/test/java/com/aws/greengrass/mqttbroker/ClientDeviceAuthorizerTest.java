/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.AuthorizationRequest;
import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.device.exception.AuthorizationException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.testcommons.testutilities.GGServiceTestUtil;
import io.moquette.broker.security.ClientData;
import io.moquette.broker.subscriptions.Topic;
import io.moquette.interception.messages.InterceptDisconnectMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class ClientDeviceAuthorizerTest extends GGServiceTestUtil {
    @Mock
    ClientDeviceTrustManager mockTrustManager;

    @Mock
    DeviceAuthClient mockDeviceAuthClient;

    @Mock
    X509Certificate mockCertificate;

    private static final String DEFAULT_SESSION = "SESSION_ID";
    private static final String DEFAULT_CLIENT = "clientId";
    private static final String DEFAULT_TOPIC = "topic";

    void configureAuthResponse(String session, String clientId, String operation, String resource, boolean doAllow) throws AuthorizationException {
        AuthorizationRequest authorizationRequest = AuthorizationRequest.builder()
            .sessionId(session)
            .clientId(clientId)
            .operation(operation)
            .resource(resource)
            .build();
        when(mockDeviceAuthClient.canDevicePerform(authorizationRequest))
            .thenReturn(doAllow);
    }

    void configureConnectResponse(String session, String clientId, boolean doAllow) throws AuthorizationException {
        configureAuthResponse(session, clientId, "mqtt:connect", "mqtt:clientId:" + clientId, doAllow);
    }

    void configureConnectResponse(boolean doAllow) throws AuthorizationException {
        configureConnectResponse(DEFAULT_SESSION, DEFAULT_CLIENT, doAllow);
    }

    void configurePublishResponse(String session, String clientId, String topic, boolean doAllow) throws AuthorizationException {
        configureAuthResponse(session, clientId, "mqtt:publish", "mqtt:topic:" + topic, doAllow);
    }

    void configurePublishResponse(boolean doAllow) throws AuthorizationException {
        configurePublishResponse(DEFAULT_SESSION, DEFAULT_CLIENT, DEFAULT_TOPIC, doAllow);
    }

    void configureSubscribeResponse(String session, String clientId, String topic, boolean doAllow) throws AuthorizationException {
        configureAuthResponse(session, clientId, "mqtt:subscribe", "mqtt:topic:" + topic, doAllow);
    }

    void configureSubscribeResponse(boolean doAllow) throws AuthorizationException {
        configureSubscribeResponse(DEFAULT_SESSION, DEFAULT_CLIENT, DEFAULT_TOPIC, doAllow);
    }

    @Test
    void GIVEN_clientDataWithoutCertificate_WHEN_checkValid_THEN_returnsFalse() {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        ClientData clientData = new ClientData(DEFAULT_CLIENT);
        assertThat(authorizer.checkValid(clientData), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_checkValid_THEN_returnsFalse() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        ClientData clientData = new ClientData(DEFAULT_CLIENT);
        clientData.setCertificateChain(new X509Certificate[]{mockCertificate});

        when(mockTrustManager.getSessionForCertificate(any())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(false);

        assertThat(authorizer.checkValid(clientData), is(false));
    }

    @Test
    void GIVEN_authorizedClient_WHEN_checkValid_THEN_returnsTrue() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        ClientData clientData = new ClientData(DEFAULT_CLIENT);
        clientData.setCertificateChain(new X509Certificate[]{mockCertificate});

        when(mockTrustManager.getSessionForCertificate(any())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(clientData), is(true));
    }

    @Test
    void GIVEN_unknownClient_WHEN_canReadCanWrite_THEN_returnsFalse() {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_canReadCanWrite_THEN_returnsFalse() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        ClientData clientData = new ClientData(DEFAULT_CLIENT);
        clientData.setCertificateChain(new X509Certificate[]{mockCertificate});

        when(mockTrustManager.getSessionForCertificate(any())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        configureSubscribeResponse(false);
        configurePublishResponse(false);

        assertThat(authorizer.checkValid(clientData), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_canReadCanWrite_THEN_returnsTrue() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        ClientData clientData = new ClientData(DEFAULT_CLIENT);
        clientData.setCertificateChain(new X509Certificate[]{mockCertificate});

        when(mockTrustManager.getSessionForCertificate(any())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        configureSubscribeResponse(true);
        configurePublishResponse(true);

        assertThat(authorizer.checkValid(clientData), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(true));
    }

    @Test
    void GIVEN_twoClientsWithDifferingPermissions_WHEN_canReadCanWrite_THEN_correctSessionIsUsed() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        String session1 = "SESSION_ID1";
        String session2 = "SESSION_ID2";
        String client1 = "clientId1";
        String client2 = "clientId2";
        String topic1 = "topic/client1";
        String topic2 = "topic/client2";
        X509Certificate[] chain1 = {mock(X509Certificate.class)};
        X509Certificate[] chain2 = {mock(X509Certificate.class)};
        ClientData clientData1 = new ClientData(client1);
        ClientData clientData2 = new ClientData(client2);
        clientData1.setCertificateChain(chain1);
        clientData2.setCertificateChain(chain2);

        // Client1 can connect and publish/subscribe on own topic, but not client2's topics
        when(mockTrustManager.getSessionForCertificate(chain1)).thenReturn(session1);
        configureConnectResponse(session1, client1, true);
        configurePublishResponse(session1, client1, topic1, true);
        configureSubscribeResponse(session1, client1, topic1, true);
        configurePublishResponse(session1, client1, topic2, false);
        configureSubscribeResponse(session1, client1, topic2, false);

        // Client2 can connect and publish/subscribe on own topic, but not client1's topics
        when(mockTrustManager.getSessionForCertificate(chain2)).thenReturn(session2);
        configureConnectResponse(session2, client2, true);
        configurePublishResponse(session2, client2, topic1, false);
        configureSubscribeResponse(session2, client2, topic1, false);
        configurePublishResponse(session2, client2, topic2, true);
        configureSubscribeResponse(session2, client2, topic2, true);

        assertThat(authorizer.checkValid(clientData1), is(true));
        assertThat(authorizer.checkValid(clientData2), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(topic1), "", client1), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(topic1), "", client1), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(topic2), "", client1), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(topic2), "", client1), is(false));
        assertThat(authorizer.canRead(Topic.asTopic(topic1), "", client2), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(topic1), "", client2), is(false));
        assertThat(authorizer.canRead(Topic.asTopic(topic2), "", client2), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(topic2), "", client2), is(true));
    }

    @Test
    void GIVEN_authorizedClient_WHEN_postConnect_THEN_closeDCASession() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        ClientData clientData = new ClientData(DEFAULT_CLIENT);
        clientData.setCertificateChain(new X509Certificate[]{mockCertificate});

        when(mockTrustManager.getSessionForCertificate(any())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(clientData), is(true));

        authorizer.new ConnectionTerminationListener()
            .onDisconnect(new InterceptDisconnectMessage(DEFAULT_CLIENT, null));
        verify(mockDeviceAuthClient).closeSession(DEFAULT_SESSION);
        assertThat(authorizer.getSessionForClientId(DEFAULT_CLIENT), nullValue());
    }

    @Test
    void GIVEN_authorizedClient_WHEN_postConnect_and_sessionAlreadyClosed_THEN_failSafe() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        ClientData clientData = new ClientData(DEFAULT_CLIENT);
        clientData.setCertificateChain(new X509Certificate[]{mockCertificate});

        when(mockTrustManager.getSessionForCertificate(any())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        doThrow(AuthorizationException.class).when(mockDeviceAuthClient).closeSession(DEFAULT_SESSION);

        assertThat(authorizer.checkValid(clientData), is(true));

        authorizer.new ConnectionTerminationListener()
            .onDisconnect(new InterceptDisconnectMessage(DEFAULT_CLIENT, null));
        verify(mockDeviceAuthClient).closeSession(DEFAULT_SESSION);
        assertThat(authorizer.getSessionForClientId(DEFAULT_CLIENT), nullValue());
    }
}
