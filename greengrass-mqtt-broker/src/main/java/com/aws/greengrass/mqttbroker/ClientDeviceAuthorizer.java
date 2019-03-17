/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.AuthorizationRequest;
import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.device.exception.AuthorizationException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import io.moquette.broker.security.ClientData;
import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.security.IAuthorizatorPolicy;
import io.moquette.broker.subscriptions.Topic;
import io.moquette.interception.AbstractInterceptHandler;
import io.moquette.interception.InterceptHandler;
import io.moquette.interception.messages.InterceptConnectionLostMessage;
import io.moquette.interception.messages.InterceptDisconnectMessage;

import java.security.cert.X509Certificate;
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
    public boolean checkValid(ClientData clientData) {
        if (!clientData.getCertificates()
            .isPresent()) {
            LOG.error("No certificate in client data");
            return false;
        }
        X509Certificate[] certificateChain = (X509Certificate[]) clientData.getCertificates()
            .get();

        // Retrieve session ID and construct authorization request for MQTT CONNECT
        String sessionId = trustManager.getSessionForCertificate(certificateChain);
        String clientId = clientData.getClientId();
        LOG.atInfo()
            .kv(CLIENT_ID, clientId)
            .kv(SESSION_ID, sessionId)
            .log("Retrieved client session");

        boolean canConnect = canDevicePerform(sessionId, clientId, "mqtt:connect", "mqtt:clientId:" + clientId);

        // Add mapping from client id to session id for future canRead/canWrite calls
        if (canConnect) {
            LOG.atInfo()
                .kv(CLIENT_ID, clientId)
                .kv(SESSION_ID, sessionId)
                .log("Successfully authenticated client device");
            clientToSessionMap.put(clientId, sessionId);
        } else {
            LOG.atInfo()
                .kv(CLIENT_ID, clientId)
                .kv(SESSION_ID, sessionId)
                .log("Device not authorized to connect");
        }

        return canConnect;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        LOG.atDebug()
            .kv("topic", topic)
            .kv("user", user)
            .kv(CLIENT_ID, client)
            .log("MQTT publish request");
        return canDevicePerform(client, "mqtt:publish", "mqtt:topic:" + topic);
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        LOG.atDebug()
            .kv("topic", topic)
            .kv("user", user)
            .kv(CLIENT_ID, client)
            .log("MQTT subscribe request");
        return canDevicePerform(client, "mqtt:subscribe", "mqtt:topic:" + topic);
    }

    private boolean canDevicePerform(String client, String operation, String resource) {
        String sessionId = getSessionForClientId(client);
        if (sessionId == null) {
            LOG.atError()
                .kv(CLIENT_ID, client)
                .kv("operation", operation)
                .kv("resource", resource)
                .log("Unknown client request, denying request");
            return false;
        }
        return canDevicePerform(sessionId, client, operation, resource);
    }

    private boolean canDevicePerform(String session, String client, String operation, String resource) {
        try {
            AuthorizationRequest authorizationRequest = AuthorizationRequest.builder()
                .sessionId(session)
                .clientId(client)
                .operation(operation)
                .resource(resource)
                .build();
            return deviceAuthClient.canDevicePerform(authorizationRequest);
        } catch (AuthorizationException e) {
            LOG.atError()
                .kv(SESSION_ID, session)
                .cause(e)
                .log("session ID is invalid");
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
                LOG.atDebug().kv(SESSION_ID, sessionId).log("Close auth session");
                try {
                    deviceAuthClient.closeSession(sessionId);
                } catch (AuthorizationException e) {
                    LOG.atWarn()
                        .kv(CLIENT_ID, clientId)
                        .kv(SESSION_ID, sessionId)
                        .log("session is already closed");
                }
                clientToSessionMap.remove(clientId, sessionId);
            }
        }
    }

}