/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.AuthorizationRequest;
import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.device.exception.AuthenticationException;
import com.aws.greengrass.device.exception.AuthorizationException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.testcommons.testutilities.GGServiceTestUtil;
import io.moquette.broker.subscriptions.Topic;
import io.moquette.interception.messages.InterceptDisconnectMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;

import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class ClientDeviceAuthorizerTest extends GGServiceTestUtil {
    @Mock
    ClientDeviceTrustManager mockTrustManager;

    @Mock
    DeviceAuthClient mockDeviceAuthClient;

    private static final String DEFAULT_SESSION = "SESSION_ID";
    private static final String DEFAULT_CLIENT = "clientId";
    private static final String DEFAULT_PEER_CERT = "VALID_PEER_CERT";
    private static final String EMPTY_PEER_CERT = "";
    private static final String DEFAULT_TOPIC = "topic";
    private static final byte[] DEFAULT_PASSWORD = "".getBytes(StandardCharsets.UTF_8);

    void configureAuthResponse(String session, String operation, String resource, boolean doAllow)
        throws AuthorizationException {
        AuthorizationRequest authorizationRequest =
            AuthorizationRequest.builder().sessionId(session).operation(operation).resource(resource).build();
        when(mockDeviceAuthClient.canDevicePerform(authorizationRequest)).thenReturn(doAllow);
    }

    void configureConnectResponse(String session, String clientId, boolean doAllow) throws AuthorizationException {
        configureAuthResponse(session, "mqtt:connect", "mqtt:clientId:" + clientId, doAllow);
    }

    void configureConnectResponse(boolean doAllow) throws AuthorizationException {
        configureConnectResponse(DEFAULT_SESSION, DEFAULT_CLIENT, doAllow);
    }

    void configurePublishResponse(String session, String topic, boolean doAllow) throws AuthorizationException {
        configureAuthResponse(session, "mqtt:publish", "mqtt:topic:" + topic, doAllow);
    }

    void configurePublishResponse(boolean doAllow) throws AuthorizationException {
        configurePublishResponse(DEFAULT_SESSION, DEFAULT_TOPIC, doAllow);
    }

    void configureSubscribeResponse(String session, String topic, boolean doAllow) throws AuthorizationException {
        configureAuthResponse(session, "mqtt:subscribe", "mqtt:topicfilter:" + topic, doAllow);
    }

    void configureSubscribeResponse(boolean doAllow) throws AuthorizationException {
        configureSubscribeResponse(DEFAULT_SESSION, DEFAULT_TOPIC, doAllow);
    }

    @Test
    void GIVEN_clientDataWithoutCertificate_WHEN_checkValid_THEN_returnsFalse() {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        assertThat(authorizer.checkValid(DEFAULT_CLIENT, EMPTY_PEER_CERT, DEFAULT_PASSWORD), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_checkValid_THEN_returnsFalseAndClosesSession() throws Exception {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        when(mockTrustManager.getSessionForCertificate(DEFAULT_PEER_CERT)).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(false);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(false));
        verify(mockDeviceAuthClient).attachThing(DEFAULT_SESSION, DEFAULT_CLIENT);
        verify(mockDeviceAuthClient).closeSession(DEFAULT_SESSION);
    }

    @Test
    void GIVEN_duplicateClientIds_WHEN_checkValid_THEN_firstSessionClosed() throws AuthorizationException {
        final String USERNAME1 = "PeerCert1";
        final String USERNAME2 = "PeerCert2";
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        when(mockTrustManager.getSessionForCertificate(USERNAME1)).thenReturn("SESSION1");
        configureConnectResponse("SESSION1", DEFAULT_CLIENT, true);
        assertThat(authorizer.checkValid(DEFAULT_CLIENT, USERNAME1, DEFAULT_PASSWORD), is(true));
        ClientDeviceAuthorizer.UserSessionPair pair = authorizer.getSessionForClient(DEFAULT_CLIENT, USERNAME1);
        assertThat(pair.getSession(), is("SESSION1"));

        when(mockTrustManager.getSessionForCertificate(USERNAME2)).thenReturn("SESSION2");
        configureConnectResponse("SESSION2", DEFAULT_CLIENT, true);
        assertThat(authorizer.checkValid(DEFAULT_CLIENT, USERNAME2, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.getSessionForClient(DEFAULT_CLIENT, USERNAME1), is(nullValue()));
        ClientDeviceAuthorizer.UserSessionPair pair2 = authorizer.getSessionForClient(DEFAULT_CLIENT, USERNAME2);
        assertThat(pair2.getSession(), is("SESSION2"));

        verify(mockDeviceAuthClient, atMostOnce()).closeSession("SESSION1");
    }

    @Test
    void GIVEN_authorizedClient_WHEN_checkValid_THEN_returnsTrue() throws Exception {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        when(mockTrustManager.getSessionForCertificate(DEFAULT_PEER_CERT)).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
        verify(mockDeviceAuthClient).attachThing(DEFAULT_SESSION, DEFAULT_CLIENT);
    }

    @Test
    void GIVEN_attachThingThrowsException_WHEN_checkValid_THEN_returnsFalse(ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, AuthenticationException.class);
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        when(mockTrustManager.getSessionForCertificate(DEFAULT_PEER_CERT)).thenReturn(DEFAULT_SESSION);
        doThrow(AuthenticationException.class).when(mockDeviceAuthClient).attachThing(DEFAULT_SESSION, DEFAULT_CLIENT);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(false));
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

        when(mockTrustManager.getSessionForCertificate(DEFAULT_PEER_CERT)).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        configureSubscribeResponse(false);
        configurePublishResponse(false);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_canReadCanWrite_THEN_returnsTrue() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        when(mockTrustManager.getSessionForCertificate(DEFAULT_PEER_CERT)).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        configureSubscribeResponse(true);
        configurePublishResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(true));
    }

    @Test
    void GIVEN_twoClientsWithDifferingPermissions_WHEN_canReadCanWrite_THEN_correctSessionIsUsed()
        throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);
        String session1 = "SESSION_ID1";
        String session2 = "SESSION_ID2";
        String client1 = "clientId1";
        String client2 = "clientId2";
        String cert1 = "PeerCert1";
        String cert2 = "PeerCert2";
        String topic1 = "topic/client1";
        String topic2 = "topic/client2";

        // Client1 can connect and publish/subscribe on own topic, but not client2's topics
        when(mockTrustManager.getSessionForCertificate(cert1)).thenReturn(session1);
        configureConnectResponse(session1, client1, true);
        configurePublishResponse(session1, topic1, true);
        configureSubscribeResponse(session1, topic1, true);
        configurePublishResponse(session1, topic2, false);
        configureSubscribeResponse(session1, topic2, false);

        // Client2 can connect and publish/subscribe on own topic, but not client1's topics
        when(mockTrustManager.getSessionForCertificate(cert2)).thenReturn(session2);
        configureConnectResponse(session2, client2, true);
        configurePublishResponse(session2, topic1, false);
        configureSubscribeResponse(session2, topic1, false);
        configurePublishResponse(session2, topic2, true);
        configureSubscribeResponse(session2, topic2, true);

        assertThat(authorizer.checkValid(client1, cert1, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.checkValid(client2, cert2, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(topic1), cert1, client1), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(topic1), cert1, client1), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(topic2), cert1, client1), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(topic2), cert1, client1), is(false));
        assertThat(authorizer.canRead(Topic.asTopic(topic1), cert2, client2), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(topic1), cert2, client2), is(false));
        assertThat(authorizer.canRead(Topic.asTopic(topic2), cert2, client2), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(topic2), cert2, client2), is(true));
    }

    @Test
    void GIVEN_authorizedClient_WHEN_onDisconnect_THEN_closeCDASession() throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        when(mockTrustManager.getSessionForCertificate(DEFAULT_PEER_CERT)).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));

        authorizer.new ConnectionTerminationListener()
            .onDisconnect(new InterceptDisconnectMessage(DEFAULT_CLIENT, DEFAULT_PEER_CERT));
        verify(mockDeviceAuthClient).closeSession(DEFAULT_SESSION);
        assertThat(authorizer.getSessionForClient(DEFAULT_CLIENT, DEFAULT_PEER_CERT), nullValue());
    }

    @Test
    void GIVEN_authorizedClient_WHEN_onDisconnect_and_sessionAlreadyClosed_THEN_failSafe()
        throws AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockTrustManager, mockDeviceAuthClient);

        when(mockTrustManager.getSessionForCertificate(DEFAULT_PEER_CERT)).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        doThrow(AuthorizationException.class).when(mockDeviceAuthClient).closeSession(DEFAULT_SESSION);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));

        authorizer.new ConnectionTerminationListener()
            .onDisconnect(new InterceptDisconnectMessage(DEFAULT_CLIENT, DEFAULT_PEER_CERT));
        verify(mockDeviceAuthClient).closeSession(DEFAULT_SESSION);
        assertThat(authorizer.getSessionForClient(DEFAULT_CLIENT, DEFAULT_PEER_CERT), nullValue());
    }
}
