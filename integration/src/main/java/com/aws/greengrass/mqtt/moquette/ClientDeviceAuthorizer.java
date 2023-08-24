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
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.security.IAuthorizatorPolicy;
import io.moquette.broker.subscriptions.Topic;
import io.moquette.interception.AbstractInterceptHandler;
import io.moquette.interception.InterceptHandler;
import io.moquette.interception.messages.InterceptConnectionLostMessage;
import io.moquette.interception.messages.InterceptDisconnectMessage;

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
            sessionPair = getOrCreateSessionForClient(clientId, username);
            sessionId = sessionPair.getSession();
        } catch (AuthenticationException e) {
            LOG.atWarn().cause(e).kv(CLIENT_ID, clientId)
                .log("Can't create auth session. Check that the thing connects using its thing name as the "
                    + "client ID and has a valid AWS IoT client certificate.");
            return false;
        }
        boolean canConnect = false;
        try {
            canConnect = canDevicePerform(sessionId, "mqtt:connect", "mqtt:clientId:" + clientId);
        } catch (InvalidSessionException e) {
            LOG.debug("{}: {}", e.getClass().getSimpleName(), e.getMessage());
            // Remove session in Moquette since it's not in CDA
            clientToSessionMap.remove(clientId, sessionPair);
            try {
                sessionPair = getOrCreateSessionForClient(clientId, username);
                sessionId = sessionPair.getSession();
            } catch (AuthenticationException err) {
                LOG.atWarn().cause(err).kv(CLIENT_ID, clientId)
                    .log("Can't create auth session. Check that the thing connects using its thing name as the "
                        + "client ID and has a valid AWS IoT client certificate.");
                return false;
            }
            try {
                canConnect = canDevicePerform(sessionId, "mqtt:connect", "mqtt:clientId:" + clientId);
            } catch (InvalidSessionException err) {
                LOG.error("{}: {}", err.getClass().getSimpleName(), err.getMessage());
                // Remove session in Moquette since it's not in CDA
                clientToSessionMap.remove(clientId, sessionPair);
            } catch (AuthorizationException err) {
                LOG.atWarn().kv(SESSION_ID, sessionId).cause(err).log("Authorization Exception");
            }
        } catch (AuthorizationException e) {
            LOG.atWarn().kv(SESSION_ID, sessionId).cause(e).log("Authorization Exception");
        }

        // Add mapping from client id to session id for future canRead/canWrite calls
        if (canConnect) {
            LOG.atInfo().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId)
                .log("Successfully authenticated client device");
            String finalSessionId = sessionId;
            clientToSessionMap.compute(clientId, (k, v) -> {
                if (v != null && !(finalSessionId.equals(v.getSession()))) {
                    LOG.atWarn().kv(CLIENT_ID, clientId).kv("Previous auth session", v.getSession())
                        .log("Duplicate client ID detected. Closing old auth session.");
                    clientDevicesAuthService.closeClientDeviceAuthSession(v.getSession());
                }
                return new UserSessionPair(username, finalSessionId);
            });
        } else {
            LOG.atWarn().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Device isn't authorized to connect");
            clientDevicesAuthService.closeClientDeviceAuthSession(sessionId);
        }

        return canConnect;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        String resource = "mqtt:topic:" + topic;
        boolean canPerform = canDevicePerform(client, user, "mqtt:publish", resource);
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT publish request");
        return canPerform;
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        String resource = "mqtt:topicfilter:" + topic;
        boolean canPerform = canDevicePerform(client, user, "mqtt:subscribe", resource);
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT subscribe request");
        return canPerform;
    }

    private boolean canDevicePerform(String client, String user, String operation, String resource) {
        boolean canPerform = false;
        try {
            UserSessionPair sessionPair = getOrCreateSessionForClient(client, user);
            if (sessionPair == null) {
                return false;
            }
            try {
                canPerform = canDevicePerform(sessionPair.getSession(), operation, resource);
            } catch (InvalidSessionException e) {
                LOG.atError().kv(SESSION_ID, sessionPair.getSession()).cause(e).log("Session ID is invalid");
                // Remove session in Moquette since it's not in CDA
                clientToSessionMap.remove(client, sessionPair);
            } catch (AuthorizationException e) {
                LOG.atError().kv(SESSION_ID, sessionPair.getSession()).cause(e).log("Authorization Exception");
            }
        } catch (AuthenticationException e) {
            LOG.atWarn().cause(e).kv(CLIENT_ID, client).log("Unable to re-authenticate client.");
        }
        return canPerform;
    }

    private boolean canDevicePerform(String sessionId, String operation, String resource) throws
        AuthorizationException {
        AuthorizationRequest authorizationRequest =
            AuthorizationRequest.builder().sessionId(sessionId).operation(operation).resource(resource).build();
        return clientDevicesAuthService.authorizeClientDeviceAction(authorizationRequest);
    }

    UserSessionPair getSessionForClient(String clientId, String username) {
        UserSessionPair pair = clientToSessionMap.getOrDefault(clientId, null);
        if (pair != null && pair.getUsername().equals(username)) {
            return pair;
        }
        return null;
    }

    UserSessionPair getOrCreateSessionForClient(String clientId, String username) throws AuthenticationException {
        UserSessionPair pair = getSessionForClient(clientId, username);
        if (pair != null) {
            return pair;
        }
        return createSessionForClient(clientId, username);
    }

    UserSessionPair createSessionForClient(String clientId, String username) throws AuthenticationException {
        Map<String, String> mqttCredentials = new HashMap<>();
        mqttCredentials.put(CERTIFICATE_PEM, username); // Client certificate is passed as username
        mqttCredentials.put(CLIENT_ID, clientId);

        String sessionId = clientDevicesAuthService.getClientDeviceAuthToken(MQTT_CREDENTIAL, mqttCredentials);
        UserSessionPair sessionPair = new UserSessionPair(username, sessionId);
        clientToSessionMap.put(clientId, sessionPair);
        return sessionPair;
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
                clientDevicesAuthService.closeClientDeviceAuthSession(sessionId);
                clientToSessionMap.remove(clientId, sessionPair);
            }
        }
    }
}
