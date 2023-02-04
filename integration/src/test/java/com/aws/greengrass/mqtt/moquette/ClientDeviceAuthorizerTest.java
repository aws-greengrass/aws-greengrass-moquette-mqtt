/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette;

import com.aws.greengrass.clientdevices.auth.AuthorizationRequest;
import com.aws.greengrass.clientdevices.auth.api.ClientDevicesAuthServiceApi;
import com.aws.greengrass.clientdevices.auth.exception.AuthenticationException;
import com.aws.greengrass.clientdevices.auth.exception.AuthorizationException;
import com.aws.greengrass.clientdevices.auth.exception.InvalidSessionException;
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
    ClientDevicesAuthServiceApi mockClientDevicesAuthService;

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
        when(mockClientDevicesAuthService.authorizeClientDeviceAction(authorizationRequest)).thenReturn(doAllow);
    }

    void configureAuthResponseException(String session, String operation, String resource, boolean doAllow)
        throws AuthorizationException {
        AuthorizationRequest authorizationRequest =
            AuthorizationRequest.builder().sessionId(session).operation(operation).resource(resource).build();
        when(mockClientDevicesAuthService.authorizeClientDeviceAction(authorizationRequest))
            .thenThrow(new InvalidSessionException(String.format("Invalid session ID (%s)", session)))
            .thenReturn(doAllow);
    }

    void configureConnectResponse(String session, String clientId, boolean doAllow) throws AuthorizationException {
        configureAuthResponse(session, "mqtt:connect", "mqtt:clientId:" + clientId, doAllow);
    }

    void configureConnectResponse(boolean doAllow) throws AuthorizationException {
        configureConnectResponse(DEFAULT_SESSION, DEFAULT_CLIENT, doAllow);
    }

    void configureConnectResponseException(String session, String clientId, boolean doAllow) throws AuthorizationException {
        configureAuthResponseException(session, "mqtt:connect", "mqtt:clientId:" + clientId, doAllow);
    }

    void configureConnectResponseException(boolean doAllow) throws AuthorizationException {
        configureConnectResponseException(DEFAULT_SESSION, DEFAULT_CLIENT, doAllow);
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
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);
        assertThat(authorizer.checkValid(DEFAULT_CLIENT, EMPTY_PEER_CERT, DEFAULT_PASSWORD), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_checkValid_THEN_returnsFalseAndClosesSession() throws Exception {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(false);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(false));
        verify(mockClientDevicesAuthService).closeClientDeviceAuthSession(DEFAULT_SESSION);
    }

    @Test
    void GIVEN_duplicateClientIds_WHEN_checkValid_THEN_firstSessionClosed() throws AuthenticationException,
        AuthorizationException {
        final String USERNAME1 = "PeerCert1";
        final String USERNAME2 = "PeerCert2";
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn("SESSION1");
        configureConnectResponse("SESSION1", DEFAULT_CLIENT, true);
        assertThat(authorizer.checkValid(DEFAULT_CLIENT, USERNAME1, DEFAULT_PASSWORD), is(true));
        ClientDeviceAuthorizer.UserSessionPair pair = authorizer.getSessionForClient(DEFAULT_CLIENT, USERNAME1);
        assertThat(pair.getSession(), is("SESSION1"));

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn("SESSION2");
        configureConnectResponse("SESSION2", DEFAULT_CLIENT, true);
        assertThat(authorizer.checkValid(DEFAULT_CLIENT, USERNAME2, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.getSessionForClient(DEFAULT_CLIENT, USERNAME1), is(nullValue()));
        ClientDeviceAuthorizer.UserSessionPair pair2 = authorizer.getSessionForClient(DEFAULT_CLIENT, USERNAME2);
        assertThat(pair2.getSession(), is("SESSION2"));

        verify(mockClientDevicesAuthService).closeClientDeviceAuthSession("SESSION1");
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_checkValid_THEN_returnsFalse(ExtensionContext context)
        throws AuthenticationException {
        ignoreExceptionOfType(context, AuthenticationException.class);

        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenThrow(
            new AuthenticationException("Invalid client"));

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(false));
    }

    @Test
    void GIVEN_authorizedClient_WHEN_checkValid_THEN_returnsTrue() throws Exception {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
    }

    @Test
    void GIVEN_unknownClient_WHEN_canReadCanWrite_THEN_returnsFalse(ExtensionContext context)
        throws AuthenticationException {
        ignoreExceptionOfType(context, AuthenticationException.class);

        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenThrow(
            new AuthenticationException("Invalid client"));

        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), "user", DEFAULT_CLIENT), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_canReadCanWrite_THEN_returnsFalse() throws AuthenticationException, AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        configureSubscribeResponse(false);
        configurePublishResponse(false);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(false));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(false));
    }

    @Test
    void GIVEN_unauthorizedClient_WHEN_canReadCanWrite_THEN_returnsTrue() throws AuthenticationException, AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);
        configureSubscribeResponse(true);
        configurePublishResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(true));
    }

    @Test
    void GIVEN_twoClientsWithDifferingPermissions_WHEN_canReadCanWrite_THEN_correctSessionIsUsed()
        throws AuthenticationException, AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);
        String session1 = "SESSION_ID1";
        String session2 = "SESSION_ID2";
        String client1 = "clientId1";
        String client2 = "clientId2";
        String cert1 = "PeerCert1";
        String cert2 = "PeerCert2";
        String topic1 = "topic/client1";
        String topic2 = "topic/client2";

        // Client1 can connect and publish/subscribe on own topic, but not client2's topics
        configureConnectResponse(session1, client1, true);
        configurePublishResponse(session1, topic1, true);
        configureSubscribeResponse(session1, topic1, true);
        configurePublishResponse(session1, topic2, false);
        configureSubscribeResponse(session1, topic2, false);

        // Client2 can connect and publish/subscribe on own topic, but not client1's topics
        configureConnectResponse(session2, client2, true);
        configurePublishResponse(session2, topic1, false);
        configureSubscribeResponse(session2, topic1, false);
        configurePublishResponse(session2, topic2, true);
        configureSubscribeResponse(session2, topic2, true);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(session1);
        assertThat(authorizer.checkValid(client1, cert1, DEFAULT_PASSWORD), is(true));
        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(session2);
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
    void GIVEN_authorizedClient_WHEN_onDisconnect_THEN_closeAuthSession() throws AuthenticationException,
        AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));

        authorizer.new ConnectionTerminationListener()
            .onDisconnect(new InterceptDisconnectMessage(DEFAULT_CLIENT, DEFAULT_PEER_CERT));
        verify(mockClientDevicesAuthService).closeClientDeviceAuthSession(DEFAULT_SESSION);
        assertThat(authorizer.getSessionForClient(DEFAULT_CLIENT, DEFAULT_PEER_CERT), nullValue());
    }

    @Test
    void GIVEN_authorizedClientAndInvalidSession_WHEN_canReadCanWrite_THEN_returnsTrue(ExtensionContext context) throws
        AuthenticationException, AuthorizationException {
        ignoreExceptionOfType(context, InvalidSessionException.class);
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponseException(true);
        configureSubscribeResponse(true);
        configurePublishResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
        assertThat(authorizer.canRead(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(true));
        assertThat(authorizer.canWrite(Topic.asTopic(DEFAULT_TOPIC), DEFAULT_PEER_CERT, DEFAULT_CLIENT), is(true));
    }

    @Test
    void GIVEN_authorizedClient_WHEN_onDisconnectAndCheckValid_THEN_returnTrue() throws AuthenticationException,
        AuthorizationException {
        ClientDeviceAuthorizer authorizer = new ClientDeviceAuthorizer(mockClientDevicesAuthService);

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));

        authorizer.new ConnectionTerminationListener()
            .onDisconnect(new InterceptDisconnectMessage(DEFAULT_CLIENT, DEFAULT_PEER_CERT));
        verify(mockClientDevicesAuthService).closeClientDeviceAuthSession(DEFAULT_SESSION);
        assertThat(authorizer.getSessionForClient(DEFAULT_CLIENT, DEFAULT_PEER_CERT), nullValue());

        when(mockClientDevicesAuthService.getClientDeviceAuthToken(anyString(), anyMap())).thenReturn(DEFAULT_SESSION);
        configureConnectResponse(true);

        assertThat(authorizer.checkValid(DEFAULT_CLIENT, DEFAULT_PEER_CERT, DEFAULT_PASSWORD), is(true));
    }
}
