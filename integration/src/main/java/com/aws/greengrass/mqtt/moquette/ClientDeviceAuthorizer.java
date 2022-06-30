/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette;

import com.aws.greengrass.clientdevices.auth.AuthorizationRequest;
import com.aws.greengrass.clientdevices.auth.api.ClientDevicesAuthServiceApi;
import com.aws.greengrass.clientdevices.auth.exception.AuthenticationException;
import com.aws.greengrass.clientdevices.auth.exception.AuthorizationException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.mqtt.moquette.metrics.MoquetteMqttMetricsEmmitter;
import com.aws.greengrass.mqtt.moquette.metrics.MqttMetrics;
import com.aws.greengrass.telemetry.impl.Metric;
import com.aws.greengrass.telemetry.models.TelemetryAggregation;
import com.aws.greengrass.telemetry.models.TelemetryUnit;
import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.security.IAuthorizatorPolicy;
import io.moquette.broker.subscriptions.Topic;
import io.moquette.interception.AbstractInterceptHandler;
import io.moquette.interception.InterceptHandler;
import io.moquette.interception.messages.InterceptConnectionLostMessage;
import io.moquette.interception.messages.InterceptDisconnectMessage;

import java.time.Instant;
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
    private final MoquetteMqttMetricsEmmitter metricsEmitter;
    private final Map<String, UserSessionPair> clientToSessionMap;

    /**
     * Constructor.
     *
     * @param clientDevicesAuthService Client devices auth service handle
     * @param metricsEmmitter MQTT metrics emitter
     */
    public ClientDeviceAuthorizer(ClientDevicesAuthServiceApi clientDevicesAuthService,
                                  MoquetteMqttMetricsEmmitter metricsEmmitter) {
        this.clientDevicesAuthService = clientDevicesAuthService;
        this.metricsEmitter = metricsEmmitter;
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

        boolean canConnect = canDevicePerform(sessionId, "mqtt:connect", "mqtt:clientId:" + clientId);

        // Add mapping from client id to session id for future canRead/canWrite calls
        if (canConnect) {
            LOG.atInfo().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId)
                .log("Successfully authenticated client device");
            clientToSessionMap.compute(clientId, (k, v) -> {
                if (v != null) {
                    LOG.atWarn().kv(CLIENT_ID, clientId).kv("Previous auth session", v.getSession())
                        .log("Duplicate client ID detected. Closing old auth session.");
                    clientDevicesAuthService.closeClientDeviceAuthSession(v.getSession());
                }
                return new UserSessionPair(username, sessionId);
            });
        } else {
            LOG.atWarn().kv(CLIENT_ID, clientId).kv(SESSION_ID, sessionId).log("Device isn't authorized to connect");
            clientDevicesAuthService.closeClientDeviceAuthSession(sessionId);
            emitAuthErrorMetric("mqtt:connect");
        }

        return canConnect;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        String resource = "mqtt:topic:" + topic;
        boolean canPerform = false;
        String publishOp = "mqtt:publish";
        try {
            canPerform = canDevicePerform(getOrCreateSessionForClient(client, user), publishOp, resource);
        } catch (AuthenticationException e) {
            LOG.atWarn().cause(e).kv(CLIENT_ID, client).log("Unable to re-authenticate client.");
            emitAuthErrorMetric(publishOp);
        }
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT publish request");

        if (!canPerform) {
            emitAuthErrorMetric(publishOp);
        }
        return canPerform;
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        String resource = "mqtt:topicfilter:" + topic;
        boolean canPerform = false;
        String subscribeOp = "mqtt:subscribe";
        try {
            canPerform = canDevicePerform(getOrCreateSessionForClient(client, user), subscribeOp, resource);
        } catch (AuthenticationException e) {
            LOG.atWarn().cause(e).kv(CLIENT_ID, client).log("Unable to re-authenticate client.");
            emitAuthErrorMetric(subscribeOp);
        }
        LOG.atDebug().kv("topic", topic).kv("isAllowed", canPerform).kv(CLIENT_ID, client)
            .log("MQTT subscribe request");

        if (!canPerform) {
            emitAuthErrorMetric(subscribeOp);
        }
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

    /**
     * Emits MQTT AuthError metrics for requested MQTT operation.
     * Ideally these metrics should be emitted from the Moquette request handlers.
     * Emitting metrics from Authorizer integration to avoid broker code change.
     *
     * @param operation Requested MQTT operation
     */
    private void emitAuthErrorMetric(String operation) {
        String authErrorMetric;
        switch (operation) {
            case "mqtt:connect":
                authErrorMetric = MqttMetrics.CONNECT_AUTH_ERROR;
                break;
            case "mqtt:publish" :
                authErrorMetric = MqttMetrics.PUBLISH_IN_AUTH_ERROR;
                break;
            case "mqtt:subscribe" :
                authErrorMetric = MqttMetrics.SUBSCRIBE_AUTH_ERROR;
                break;
            default:
                authErrorMetric = MqttMetrics.UNKNOWN_AUTH_ERROR;
                break;
        }
        metricsEmitter.emitMetric(Metric.builder()
            .namespace(MqttMetrics.MOQUETTE_MQTT_NAMESPACE)
            .name(authErrorMetric)
            .unit(TelemetryUnit.Count)
            .aggregation(TelemetryAggregation.Sum)
            .value(1)
            .timestamp(Instant.now().toEpochMilli())
            .build());
    }
}
