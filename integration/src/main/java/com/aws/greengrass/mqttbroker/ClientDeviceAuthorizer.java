/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.AuthorizationRequest;
import com.aws.greengrass.device.ClientDevicesAuthServiceApi;
import com.aws.greengrass.device.exception.AuthenticationException;
import com.aws.greengrass.device.exception.AuthorizationException;
import com.aws.greengrass.device.exception.InvalidSessionException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.security.IAuthorizatorPolicy;
import io.moquette.broker.subscriptions.Topic;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ClientDeviceAuthorizer implements IAuthenticator, IAuthorizatorPolicy {
    private static final Logger LOG = LogManager.getLogger(ClientDeviceAuthorizer.class);
    private static final String CLIENT_ID = "clientId";
    private static final String CERTIFICATE_PEM = "certificatePem";
    private static final String SESSION_ID = "sessionId";
    private static final String MQTT_CREDENTIAL = "mqtt";

    private final ClientDevicesAuthServiceApi clientDevicesAuthService;
    private final Map<String, UserSessionPair> clientToSessionMap;

    /**
     * Constructor.
     *
     * @param clientDevicesAuthService Client devices auth service handle
     */
    public ClientDeviceAuthorizer(ClientDevicesAuthServiceApi clientDevicesAuthService) {
        this.clientDevicesAuthService = clientDevicesAuthService;
        this.clientToSessionMap = new ConcurrentHashMap<>();
    }

    @Override
    public boolean checkValid(String clientId, String username, byte[] password) {
        if (username == null || username.isEmpty()) {
            LOG.atWarn().kv(CLIENT_ID, clientId).log("No peer certificate provided");
            return false;
        }

        // Retrieve session ID and construct authorization request for MQTT CONNECT
        UserSessionPair sessionPair;
        String sessionId;
        try {
            sessionPair = getSessionForClient(clientId, username);
            sessionId = sessionPair.getSession();
        } catch (AuthenticationException e) {
            LOG.atWarn().kv(CLIENT_ID, clientId)
                .log("Can't create auth session. Check that the thing connects using its thing name as the "
                    + "client ID and has a valid AWS IoT client certificate.");
            return false;
        }

        boolean canConnect = canDevicePerform(sessionId, "mqtt:connect", "mqtt:clientId:" + clientId);

        // Add mapping from client id to session id for future canRead/canWrite calls
        if (canConnect) {
            LOG.atInfo().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId)
                .log("Successfully authenticated client device");
            clientToSessionMap.put(clientId, sessionPair);
        } else {
            LOG.atWarn().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Device isn't authorized to connect");
        }

        return canConnect;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        String resource = "mqtt:topic:" + topic;
        boolean canPerform = false;
        try {
            canPerform = canDevicePerform(getSessionForClient(client, user), "mqtt:publish", resource);
        } catch (AuthenticationException e) {
            LOG.atWarn().kv(CLIENT_ID, client).log("Unable to re-authenticate client.");
        }
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT publish request");
        return canPerform;
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        String resource = "mqtt:topicfilter:" + topic;
        boolean canPerform = false;
        try {
            canPerform = canDevicePerform(getSessionForClient(client, user), "mqtt:subscribe", resource);
        } catch (AuthenticationException e) {
            LOG.atWarn().kv(CLIENT_ID, client).log("Unable to re-authenticate client.");
        }
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT subscribe request");
        return canPerform;
    }

    private boolean canDevicePerform(UserSessionPair sessionPair, String operation, String resource) {
        if (sessionPair == null) {
            return false;
        }

        return canDevicePerform(sessionPair.getSession(), operation, resource);
    }

    private boolean canDevicePerform(String sessionId, String operation, String resource) {
        try {
            AuthorizationRequest authorizationRequest =
                AuthorizationRequest.builder().sessionId(sessionId).operation(operation).resource(resource).build();
            return clientDevicesAuthService.authorizeClientDeviceAction(authorizationRequest);
        } catch (AuthorizationException e) {
            LOG.atError().kv(SESSION_ID, sessionId).cause(e).log("Session ID is invalid");
        }
        return false;
    }

    UserSessionPair getSessionForClient(String clientId, String username) throws AuthenticationException {
        UserSessionPair pair = clientToSessionMap.getOrDefault(clientId, null);
        if (pair != null && pair.getUsername().equals(username)) {
            return pair;
        }
        return createSessionForClient(clientId, username);
    }

    UserSessionPair createSessionForClient(String clientId, String username) throws AuthenticationException {
        Map<String, String> mqttCredentials = new HashMap<>();
        mqttCredentials.put(CERTIFICATE_PEM, username); // Client certificate is passed as username
        mqttCredentials.put(CLIENT_ID, clientId);

        String sessionId = clientDevicesAuthService.getClientDeviceAuthToken(MQTT_CREDENTIAL, mqttCredentials);
        return new UserSessionPair(username, sessionId);
    }

    class UserSessionPair {
        String username;
        String sessionId;

        public UserSessionPair(String username, String sessionId) {
            this.username = username;
            this.sessionId = sessionId;
        }

        public String getUsername() {
            return username;
        }

        public String getSession() {
            return sessionId;
        }
    }
}
