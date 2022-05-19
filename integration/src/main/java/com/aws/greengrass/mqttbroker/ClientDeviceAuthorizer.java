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
    private final Map<String, String> clientToSessionMap;

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
        if (username.isEmpty()) {
            LOG.error("No peer certificate provided");
            return false;
        }

        // Retrieve session ID and construct authorization request for MQTT CONNECT
        String sessionId = trustManager.getSessionForCertificate(username);
        LOG.atInfo().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Retrieved client session");

        try {
            deviceAuthClient.attachThing(sessionId, clientId);
        } catch (AuthenticationException e) {
            LOG.atWarn().cause(e).kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId)
                .log("Can't attach thing to auth session. Check that the thing connects using its thing name as the "
                    + "client ID.");
        }

        boolean canConnect = canDevicePerform(sessionId, clientId, "mqtt:connect", "mqtt:clientId:" + clientId);

        // Add mapping from client id to session id for future canRead/canWrite calls
        if (canConnect) {
            LOG.atInfo().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId)
                .log("Successfully authenticated client device");

            // Logic for handling duplicate client IDs is unintuitive. Here, we will return true
            // so Moquette will disconnect the old connection and allow the new connection. However,
            // after returning, there is a short period of time where authZ or disconnect callbacks
            // for a given client ID could map to one of two sessions and we have no way of knowing
            // which to use.
            // In order to avoid subtle races and potential privilege escalation, we close both auth
            // sessions. Unfortunately, this means that the next authZ call for the newly connecting
            // client will fail and the client will be disconnected. This is non-ideal, but safe.
            // The client can simply reconnect and everything will work.
            clientToSessionMap.compute(clientId, (k, v) -> {
                if (v == null) {
                    return sessionId;
                } else {
                    LOG.atWarn().kv(CLIENT_ID, clientId).kv("Session 1", v).kv("Session 2", sessionId)
                        .log("Duplicate client ID detected. Closing both auth sessions.");
                    closeSession(v);
                    closeSession(sessionId);
                    return null;
                }
            });
        } else {
            LOG.atInfo().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Device isn't authorized to connect");
            closeSession(sessionId);
        }

        return canConnect;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        LOG.atDebug().kv("topic", topic).kv("user", user).kv(CLIENT_ID, client).log("MQTT publish request");
        return canDevicePerform(client, "mqtt:publish", "mqtt:topic:" + topic);
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        LOG.atDebug().kv("topic", topic).kv("user", user).kv(CLIENT_ID, client).log("MQTT subscribe request");
        return canDevicePerform(client, "mqtt:subscribe", "mqtt:topicfilter:" + topic);
    }

    private void closeSession(String sessionId) {
        try {
            deviceAuthClient.closeSession(sessionId);
        } catch (AuthorizationException e) {
            LOG.atWarn().cause(e).kv(SESSION_ID, sessionId).log("Failed to close session");
        }
    }

    private boolean canDevicePerform(String client, String operation, String resource) {
        return canDevicePerform(getSessionForClientId(client), client, operation, resource);
    }

    private boolean canDevicePerform(String session, String client, String operation, String resource) {
        if (session == null) {
            LOG.atError().kv(CLIENT_ID, client).kv("operation", operation).kv("resource", resource)
                .log("Unknown client request, denying request");
            return false;
        }

        try {
            AuthorizationRequest authorizationRequest =
                AuthorizationRequest.builder().sessionId(session).operation(operation).resource(resource).build();
            return deviceAuthClient.canDevicePerform(authorizationRequest);
        } catch (AuthorizationException e) {
            LOG.atError().kv(SESSION_ID, session).cause(e).log("Session ID is invalid");
        }
        return false;
    }

    String getSessionForClientId(String clientId) {
        return clientToSessionMap.getOrDefault(clientId, null);
    }

    public class ConnectionTerminationListener extends AbstractInterceptHandler implements InterceptHandler {

        @Override
        public String getID() {
            return "ClientDeviceConnectionTerminationListener";
        }

        @Override
        public void onDisconnect(InterceptDisconnectMessage msg) {
            LOG.atDebug().kv(CLIENT_ID, msg.getClientID()).log("On disconnect auth session handling");
            closeAuthSession(msg.getClientID());
        }

        @Override
        public void onConnectionLost(InterceptConnectionLostMessage msg) {
            LOG.atDebug().kv(CLIENT_ID, msg.getClientID()).log("On connection lost auth session handling");
            closeAuthSession(msg.getClientID());
        }

        private void closeAuthSession(String clientId) {
            String sessionId = getSessionForClientId(clientId);
            if (sessionId != null) {
                LOG.atDebug().kv(SESSION_ID, sessionId).log("Closing auth session");
                try {
                    deviceAuthClient.closeSession(sessionId);
                } catch (AuthorizationException e) {
                    LOG.atWarn().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Session is already closed");
                }
                clientToSessionMap.remove(clientId, sessionId);
            }
        }
    }

}
