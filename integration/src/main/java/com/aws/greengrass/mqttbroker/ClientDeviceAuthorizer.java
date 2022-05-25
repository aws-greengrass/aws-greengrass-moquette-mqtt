/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.AuthorizationRequest;
import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.device.exception.AuthenticationException;
import com.aws.greengrass.device.exception.AuthorizationException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.security.IAuthorizatorPolicy;
import io.moquette.broker.subscriptions.Topic;
import io.moquette.interception.AbstractInterceptHandler;
import io.moquette.interception.InterceptHandler;
import io.moquette.interception.messages.InterceptConnectionLostMessage;
import io.moquette.interception.messages.InterceptDisconnectMessage;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ClientDeviceAuthorizer implements IAuthenticator, IAuthorizatorPolicy {
    private static final Logger LOG = LogManager.getLogger(ClientDeviceAuthorizer.class);
    private static final String CLIENT_ID = "clientId";
    private static final String SESSION_ID = "sessionId";

    private final ClientDeviceTrustManager trustManager;
    private final DeviceAuthClient deviceAuthClient;
    private final Map<String, UserSessionPair> clientToSessionMap;

    /**
     * Constructor.
     *
     * @param trustManager     Trust manager
     * @param deviceAuthClient Device auth client
     */
    public ClientDeviceAuthorizer(ClientDeviceTrustManager trustManager, DeviceAuthClient deviceAuthClient) {
        this.trustManager = trustManager;
        this.deviceAuthClient = deviceAuthClient;
        this.clientToSessionMap = new ConcurrentHashMap<>();
    }

    @Override
    public boolean checkValid(String clientId, String username, byte[] password) {
        if (username == null || username.isEmpty()) {
            LOG.atWarn().kv(CLIENT_ID, clientId).log("No peer certificate provided");
            return false;
        }

        // Retrieve session ID and construct authorization request for MQTT CONNECT
        String sessionId = trustManager.getSessionForCertificate(username);
        try {
            deviceAuthClient.attachThing(sessionId, clientId);
        } catch (AuthenticationException e) {
            LOG.atWarn().cause(e).kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId)
                .log("Can't attach thing to auth session. Check that the thing connects using its thing name as the "
                    + "client ID.");
        }

        boolean canConnect = canDevicePerform(sessionId, "mqtt:connect", "mqtt:clientId:" + clientId);

        // Add mapping from client id to session id for future canRead/canWrite calls
        if (canConnect) {
            LOG.atInfo().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId)
                .log("Successfully authenticated client device");

            clientToSessionMap.compute(clientId, (k, v) -> {
                if (v != null) {
                    LOG.atWarn().kv(CLIENT_ID, clientId).kv("Previous auth session", v.getSession())
                        .log("Duplicate client ID detected. Closing old auth session.");
                    closeSession(v.getSession());
                }
                return new UserSessionPair(username, sessionId);
            });
        } else {
            LOG.atWarn().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Device isn't authorized to connect");
            closeSession(sessionId);
        }

        return canConnect;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        String resource = "mqtt:topic:" + topic;
        boolean canPerform = canDevicePerform(getSessionForClient(client, user), "mqtt:publish", resource);
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT publish request");
        return canPerform;
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        String resource = "mqtt:topicfilter:" + topic;
        boolean canPerform = canDevicePerform(getSessionForClient(client, user), "mqtt:subscribe", resource);
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT subscribe request");
        return canPerform;
    }

    private void closeSession(String sessionId) {
        try {
            deviceAuthClient.closeSession(sessionId);
        } catch (AuthorizationException e) {
            LOG.atWarn().cause(e).kv(SESSION_ID, sessionId).log("Failed to close session");
        }
    }

    private boolean canDevicePerform(String sessionId, String operation, String resource) {
        try {
            AuthorizationRequest authorizationRequest =
                AuthorizationRequest.builder().sessionId(sessionId).operation(operation).resource(resource).build();
            return deviceAuthClient.canDevicePerform(authorizationRequest);
        } catch (AuthorizationException e) {
            LOG.atError().kv(SESSION_ID, sessionId).cause(e).log("Session ID is invalid");
        }
        return false;
    }

    private boolean canDevicePerform(UserSessionPair sessionPair, String operation, String resource) {
        if (sessionPair == null) {
            return false;
        }

        return canDevicePerform(sessionPair.getSession(), operation, resource);
    }

    UserSessionPair getSessionForClient(String clientId, String username) {
        UserSessionPair pair = clientToSessionMap.getOrDefault(clientId, null);
        if (pair != null && pair.getUsername().equals(username)) {
            return pair;
        }
        LOG.atDebug().kv(CLIENT_ID, clientId).log("Unable to retrieve authorization session");
        return null;
    }

    public class ConnectionTerminationListener extends AbstractInterceptHandler implements InterceptHandler {

        @Override
        public String getID() {
            return "ClientDeviceConnectionTerminationListener";
        }

        @Override
        public void onDisconnect(InterceptDisconnectMessage msg) {
            closeAuthSession(msg.getClientID(), msg.getUsername());
        }

        @Override
        public void onConnectionLost(InterceptConnectionLostMessage msg) {
            closeAuthSession(msg.getClientID(), msg.getUsername());
        }

        private void closeAuthSession(String clientId, String username) {
            UserSessionPair sessionPair = getSessionForClient(clientId, username);
            if (sessionPair != null) {
                String sessionId = sessionPair.getSession();
                LOG.atDebug().kv(SESSION_ID, sessionId).log("Closing auth session");
                try {
                    deviceAuthClient.closeSession(sessionId);
                } catch (AuthorizationException e) {
                    // This will happen under normal operating circumstances
                    LOG.atDebug().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Session is already closed");
                }
                clientToSessionMap.remove(clientId, sessionPair);
            }
        }
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
