/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqttbroker;

import com.aws.greengrass.device.AuthorizationRequest;
import com.aws.greengrass.device.DeviceAuthClient;
import com.aws.greengrass.device.exception.AuthorizationException;
import io.moquette.broker.security.ClientData;
import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.security.IAuthorizatorPolicy;
import io.moquette.broker.subscriptions.Topic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ClientDeviceAuthorizer implements IAuthenticator, IAuthorizatorPolicy {
    private static final Logger LOG = LoggerFactory.getLogger(ClientDeviceAuthorizer.class);

    private final ClientDeviceTrustManager trustManager;
    private final DeviceAuthClient deviceAuthClient;
    private final Map<String, String> clientToSessionMap;

    /**
     * Constructor.
     * @param trustManager Trust manager
     * @param deviceAuthClient Device auth client
     */
    public ClientDeviceAuthorizer(ClientDeviceTrustManager trustManager, DeviceAuthClient deviceAuthClient) {
        this.trustManager = trustManager;
        this.deviceAuthClient = deviceAuthClient;
        this.clientToSessionMap = new ConcurrentHashMap<>();
    }

    @Override
    public boolean checkValid(ClientData clientData) {
        if (!clientData.getCertificates().isPresent()) {
            LOG.error("No certificate in client data");
            return false;
        }
        X509Certificate[] certificateChain = (X509Certificate[]) clientData.getCertificates().get();

        // Retrieve session ID and construct authorization request for MQTT CONNECT
        String sessionId = trustManager.getSessionForCertificate(certificateChain);
        String clientId = clientData.getClientId();
        LOG.info("Retrieved session for clientId={}, sessionId={}", clientId, sessionId);

        boolean canConnect = canDevicePerform(sessionId, clientId, "mqtt:connect", "mqtt:clientId:" + clientId);

        // Add mapping from client id to session id for future canRead/canWrite calls
        if (canConnect) {
            LOG.info("Successfully authenticated client device. SessionID={}, ClientID={}", sessionId, clientId);
            clientToSessionMap.put(clientId, sessionId);
        } else {
            // TODO: Need to clean up this session since the device will be disconnected
            LOG.info("Device not authorized to connect with clientId={}, sessionId={}", clientId, sessionId);
        }

        return canConnect;
    }

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        LOG.debug("canWrite({}, {}, {})", topic.toString(), user, client);
        return canDevicePerform(client, "mqtt:publish", "mqtt:topic:" + topic);
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        LOG.debug("canRead({}, {}, {})", topic.toString(), user, client);
        return canDevicePerform(client, "mqtt:subscribe", "mqtt:topic:" + topic);
    }

    private boolean canDevicePerform(String client, String operation, String resource) {
        String sessionId = getSessionForClientId(client);
        if (sessionId == null) {
            LOG.error("Unknown client request. Denying request");
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
            LOG.error("authorization exception occurred, session ID is invalid");
        }
        return false;
    }

    protected String getSessionForClientId(String clientId) {
        return clientToSessionMap.getOrDefault(clientId, null);
    }
}
