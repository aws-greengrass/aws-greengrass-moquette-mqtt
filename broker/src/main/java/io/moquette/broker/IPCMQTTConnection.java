/*
 * Copyright (c) 2012-2018 The original author or authors
 * ------------------------------------------------------
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.moquette.broker;

import io.moquette.broker.security.IAuthenticator;
import io.moquette.broker.subscriptions.Topic;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.mqtt.MqttConnectMessage;
import io.netty.handler.codec.mqtt.MqttConnectPayload;
import io.netty.handler.codec.mqtt.MqttConnectReturnCode;
import io.netty.handler.codec.mqtt.MqttFixedHeader;
import io.netty.handler.codec.mqtt.MqttMessage;
import io.netty.handler.codec.mqtt.MqttMessageBuilders;
import io.netty.handler.codec.mqtt.MqttMessageIdVariableHeader;
import io.netty.handler.codec.mqtt.MqttMessageType;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.netty.handler.codec.mqtt.MqttPublishVariableHeader;
import io.netty.handler.codec.mqtt.MqttQoS;
import io.netty.handler.codec.mqtt.MqttSubAckMessage;
import io.netty.handler.codec.mqtt.MqttSubscribeMessage;
import io.netty.handler.codec.mqtt.MqttUnsubscribeMessage;
import io.netty.handler.codec.mqtt.MqttVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static io.netty.handler.codec.mqtt.MqttConnectReturnCode.CONNECTION_REFUSED_BAD_USER_NAME_OR_PASSWORD;
import static io.netty.handler.codec.mqtt.MqttConnectReturnCode.CONNECTION_REFUSED_IDENTIFIER_REJECTED;
import static io.netty.handler.codec.mqtt.MqttConnectReturnCode.CONNECTION_REFUSED_SERVER_UNAVAILABLE;
import static io.netty.handler.codec.mqtt.MqttConnectReturnCode.CONNECTION_REFUSED_UNACCEPTABLE_PROTOCOL_VERSION;

public class IPCMQTTConnection implements IMQTTConnection {

    private static final Logger LOG = LoggerFactory.getLogger(IPCMQTTConnection.class);

    private BrokerConfiguration brokerConfig;
    private IAuthenticator authenticator;
    private SessionRegistry sessionRegistry;
    private final PostOffice postOffice;
    private boolean connected;
    private IIPCBridge ipcBridge;
    private final AtomicInteger lastPacketId = new AtomicInteger(0);
    private String clientId;
    private String username;

    IPCMQTTConnection(IIPCBridge ipcBridge, BrokerConfiguration brokerConfig, IAuthenticator authenticator,
                      SessionRegistry sessionRegistry, PostOffice postOffice) {
        this.ipcBridge = ipcBridge;
        this.brokerConfig = brokerConfig;
        this.authenticator = authenticator;
        this.sessionRegistry = sessionRegistry;
        this.postOffice = postOffice;
        this.connected = false;
    }

    /**
     * Simulate a connect message
     */
    public void connect(String clientId) {
        MqttConnectMessage msg =
            MqttMessageBuilders.connect().protocolVersion(MqttVersion.MQTT_3_1_1).clientId(clientId).cleanSession(true)
                .build();

        processConnect(msg);
    }

    /**
     * Simulate a subscribe message
     */
    public void subscribe(String topic, MqttQoS qos) {
        final MqttSubscribeMessage subscribeMsg =
            MqttMessageBuilders.subscribe().addSubscription(qos, topic).messageId(1).build();

        processSubscribe(subscribeMsg);
    }

    public void handleMessage(MqttMessage msg) {
        MqttMessageType messageType = msg.fixedHeader().messageType();
        LOG.debug("Received MQTT message, type: {}, channel: {}", messageType, "IPCMQTTConnection");
        switch (messageType) {
            case CONNECT:
                processConnect((MqttConnectMessage) msg);
                break;
            case SUBSCRIBE:
                processSubscribe((MqttSubscribeMessage) msg);
                break;
            case UNSUBSCRIBE:
                processUnsubscribe((MqttUnsubscribeMessage) msg);
                break;
            case PUBLISH:
                processPublish((MqttPublishMessage) msg);
                break;
            case PUBREC:
                processPubRec(msg);
                break;
            case PUBCOMP:
                processPubComp(msg);
                break;
            case PUBREL:
                processPubRel(msg);
                break;
            case DISCONNECT:
                processDisconnect(msg);
                break;
            case PUBACK:
                processPubAck(msg);
                break;
            case PINGREQ:
                //                MqttFixedHeader pingHeader = new MqttFixedHeader(MqttMessageType.PINGRESP, false, AT_MOST_ONCE,
                //                                                                false, 0);
                //                MqttMessage pingResp = new MqttMessage(pingHeader);
                //channel.writeAndFlush(pingResp).addListener(CLOSE_ON_FAILURE);
                break;
            default:
                LOG.error("Unknown MessageType: {}, channel: {}", messageType, "IPCMQTTConnection");
                break;
        }
    }

    private void processPubComp(MqttMessage msg) {
        final int messageID = ((MqttMessageIdVariableHeader) msg.variableHeader()).messageId();
        final Session session = sessionRegistry.retrieve(getClientId());
        session.processPubComp(messageID);
    }

    private void processPubRec(MqttMessage msg) {
        final int messageID = ((MqttMessageIdVariableHeader) msg.variableHeader()).messageId();
        final Session session = sessionRegistry.retrieve(getClientId());
        session.processPubRec(messageID);
    }

    //    static MqttMessage pubrel(int messageID) {
    //        MqttFixedHeader pubRelHeader = new MqttFixedHeader(MqttMessageType.PUBREL, false, AT_LEAST_ONCE, false, 0);
    //        return new MqttMessage(pubRelHeader, from(messageID));
    //    }

    private void processPubAck(MqttMessage msg) {
        final int messageID = ((MqttMessageIdVariableHeader) msg.variableHeader()).messageId();
        Session session = sessionRegistry.retrieve(getClientId());
        session.pubAckReceived(messageID);
    }

    void processConnect(MqttConnectMessage msg) {
        MqttConnectPayload payload = msg.payload();
        String clientId = payload.clientIdentifier();
        final String username = payload.userName();
        LOG.trace("Processing CONNECT message. CId={} username: {} channel: {}", clientId, username,
            "IPCMQTTConnection");

        if (isNotProtocolVersion(msg, MqttVersion.MQTT_3_1) && isNotProtocolVersion(msg, MqttVersion.MQTT_3_1_1)) {
            LOG.warn("MQTT protocol version is not valid. CId={} channel: {}", clientId, "IPCMQTTConnection");
            abortConnection(CONNECTION_REFUSED_UNACCEPTABLE_PROTOCOL_VERSION);
            return;
        }
        final boolean cleanSession = msg.variableHeader().isCleanSession();
        if (clientId == null || clientId.length() == 0) {
            if (!brokerConfig.isAllowZeroByteClientId()) {
                LOG.warn("Broker doesn't permit MQTT empty client ID. Username: {}, channel: {}", username,
                    "IPCMQTTConnection");
                abortConnection(CONNECTION_REFUSED_IDENTIFIER_REJECTED);
                return;
            }

            if (!cleanSession) {
                LOG.warn("MQTT client ID cannot be empty for persistent session. Username: {}, channel: {}", username,
                    "IPCMQTTConnection");
                abortConnection(CONNECTION_REFUSED_IDENTIFIER_REJECTED);
                return;
            }

            // Generating client id.
            clientId = UUID.randomUUID().toString().replace("-", "");
            LOG.debug("Client has connected with integration generated id: {}, username: {}, channel: {}", clientId,
                username, "IPCMQTTConnection");
        }

        if (!login(msg, clientId)) {
            abortConnection(CONNECTION_REFUSED_BAD_USER_NAME_OR_PASSWORD);
            //channel.close().addListener(CLOSE_ON_FAILURE);
            return;
        }

        try {
            LOG.trace("Binding MQTTConnection (channel: {}) to session", "IPCMQTTConnection");
            sessionRegistry.bindToSession(this, msg, clientId);

            // TODO: Revisit this Keep Alive logic
            //initializeKeepAliveTimeout(channel, msg, clientId);
            //setupInflightResender(channel);

            //NettyUtils.clientID(channel, clientId);
            this.clientId = clientId;
            LOG.trace("CONNACK sent, channel: {}", "IPCMQTTConnection");
            postOffice.dispatchConnection(msg);
            LOG.trace("dispatch connection: {}", msg.toString());
        } catch (SessionCorruptedException scex) {
            LOG.warn("MQTT session for client ID {} cannot be created, channel: {}", clientId, "IPCMQTTConnection");
            abortConnection(CONNECTION_REFUSED_SERVER_UNAVAILABLE);
        }
    }

    //    private void setupInflightResender(Channel channel) {
    //        channel.pipeline().addFirst("inflightResender", new InflightResender(5_000, TimeUnit.MILLISECONDS));
    //    }

    //    private void initializeKeepAliveTimeout(Channel channel, MqttConnectMessage msg, String clientId) {
    //        int keepAlive = msg.variableHeader().keepAliveTimeSeconds();
    //        NettyUtils.keepAlive(channel, keepAlive);
    //        NettyUtils.cleanSession(channel, msg.variableHeader().isCleanSession());
    //        NettyUtils.clientID(channel, clientId);
    //        int idleTime = Math.round(keepAlive * 1.5f);
    //        setIdleTime(channel.pipeline(), idleTime);
    //
    //        LOG.debug("Connection has been configured CId={}, keepAlive={}, removeTemporaryQoS2={}, idleTime={}",
    //            clientId, keepAlive, msg.variableHeader().isCleanSession(), idleTime);
    //    }

    //    private void setIdleTime(ChannelPipeline pipeline, int idleTime) {
    //        if (pipeline.names().contains("idleStateHandler")) {
    //            pipeline.remove("idleStateHandler");
    //        }
    //        pipeline.addFirst("idleStateHandler", new IdleStateHandler(idleTime, 0, 0));
    //    }

    private boolean isNotProtocolVersion(MqttConnectMessage msg, MqttVersion version) {
        return msg.variableHeader().version() != version.protocolLevel();
    }

    private void abortConnection(MqttConnectReturnCode returnCode) {
        //        MqttConnAckMessage badProto = connAck(returnCode, false);
        //        channel.writeAndFlush(badProto).addListener(FIRE_EXCEPTION_ON_FAILURE);
        //        channel.close().addListener(CLOSE_ON_FAILURE);
    }

    //    private MqttConnAckMessage connAck(MqttConnectReturnCode returnCode, boolean sessionPresent) {
    //        MqttFixedHeader mqttFixedHeader = new MqttFixedHeader(MqttMessageType.CONNACK, false, MqttQoS.AT_MOST_ONCE,
    //            false, 0);
    //        MqttConnAckVariableHeader mqttConnAckVariableHeader = new MqttConnAckVariableHeader(returnCode, sessionPresent);
    //        return new MqttConnAckMessage(mqttFixedHeader, mqttConnAckVariableHeader);
    //    }

    private boolean login(MqttConnectMessage msg, final String clientId) {
        // handle user authentication
        if (msg.variableHeader().hasUserName()) {
            byte[] pwd = null;
            if (msg.variableHeader().hasPassword()) {
                pwd = msg.payload().password().getBytes(StandardCharsets.UTF_8);
            } else if (!brokerConfig.isAllowAnonymous()) {
                LOG.error("Client didn't supply any password and MQTT anonymous mode is disabled CId={}", clientId);
                return false;
            }
            final String login = msg.payload().userName();
            if (!authenticator.checkValid(clientId, login, pwd)) {
                LOG.error("Authenticator has rejected the MQTT credentials CId={}, username={}", clientId, login);
                return false;
            }
            //NettyUtils.userName(channel, login);
            username = login;
        } else if (!brokerConfig.isAllowAnonymous()) {
            LOG.error("Client didn't supply any credentials and MQTT anonymous mode is disabled. CId={}", clientId);
            return false;
        }
        return true;
    }

    //    public void handleConnectionLost() {
    //        String clientID = getClientId();
    //        if (clientID == null || clientID.isEmpty()) {
    //            return;
    //        }
    //        LOG.info("Notifying connection lost event. CId: {}, channel: {}", clientID, "IPCMQTTConnection");
    //        Session session = sessionRegistry.retrieve(clientID);
    //        if (session.hasWill()) {
    //            postOffice.fireWill(session.getWill());
    //        }
    //        if (session.isClean()) {
    //            sessionRegistry.remove(clientID);
    //        } else {
    //            sessionRegistry.disconnect(clientID);
    //        }
    //        connected = false;
    //        //dispatch connection lost to intercept.
    //        String userName = getUsername();
    //        postOffice.dispatchConnectionLost(clientID,userName);
    //        LOG.trace("dispatch disconnection: clientId={}, userName={}", clientID, userName);
    //    }

    @Override
    public void sendConnAck(boolean isSessionAlreadyPresent) {
        connected = true;
        //        final MqttConnAckMessage ackMessage = connAck(CONNECTION_ACCEPTED, isSessionAlreadyPresent);
        //        channel.writeAndFlush(ackMessage).addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    //    boolean isConnected() {
    //        return connected;
    //    }

    @Override
    public void dropConnection() {
        //channel.close().addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    void processDisconnect(MqttMessage msg) {
        final String clientID = getClientId();
        LOG.trace("Start DISCONNECT CId={}, channel: {}", clientID, "IPCMQTTConnection");
        if (!connected) {
            LOG.info("DISCONNECT received on already closed connection, CId={}, channel: {}", clientID,
                "IPCMQTTConnection");
            return;
        }
        sessionRegistry.disconnect(clientID);
        connected = false;
        //channel.close().addListener(FIRE_EXCEPTION_ON_FAILURE);
        LOG.trace("Processed DISCONNECT CId={}, channel: {}", clientID, "IPCMQTTConnection");
        String userName = getUsername();
        postOffice.dispatchDisconnection(clientID, userName);
        LOG.trace("dispatch disconnection: clientId={}, userName={}", clientID, userName);
    }

    void processSubscribe(MqttSubscribeMessage msg) {
        final String clientID = getClientId();
        if (!connected) {
            LOG.warn("SUBSCRIBE received on already closed connection, CId={}, channel: {}", clientID,
                "IPCMQTTConnection");
            dropConnection();
            return;
        }
        postOffice.subscribeClientToTopics(msg, clientID, getUsername(), this);
    }

    @Override
    public void sendSubAckMessage(int messageID, MqttSubAckMessage ackMessage) {
        //        final String clientId = getClientId();
        //        LOG.trace("Sending SUBACK response CId={}, messageId: {}", clientId, messageID);
        //        channel.writeAndFlush(ackMessage).addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    private void processUnsubscribe(MqttUnsubscribeMessage msg) {
        List<String> topics = msg.payload().topics();
        String clientID = getClientId();

        LOG.trace("Processing UNSUBSCRIBE message. CId={}, topics: {}", clientID, topics);
        postOffice.unsubscribe(topics, this, msg.variableHeader().messageId());
    }

    @Override
    public void sendUnsubAckMessage(List<String> topics, String clientID, int messageID) {
        //        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.UNSUBACK, false, AT_MOST_ONCE,
        //            false, 0);
        //        MqttUnsubAckMessage ackMessage = new MqttUnsubAckMessage(fixedHeader, from(messageID));
        //
        //        LOG.trace("Sending UNSUBACK message. CId={}, messageId: {}, topics: {}", clientID, messageID, topics);
        //        channel.writeAndFlush(ackMessage).addListener(FIRE_EXCEPTION_ON_FAILURE);
        //        LOG.trace("Client <{}> unsubscribed from topics <{}>", clientID, topics);
    }

    void processPublish(MqttPublishMessage msg) {
        final MqttQoS qos = msg.fixedHeader().qosLevel();
        final String username = getUsername();
        final String topicName = msg.variableHeader().topicName();
        final String clientId = getClientId();
        LOG.trace("Processing PUBLISH message. CId={}, topic: {}, messageId: {}, qos: {}", clientId, topicName,
            msg.variableHeader().packetId(), qos);
        ByteBuf payload = msg.payload();
        final boolean retain = msg.fixedHeader().isRetain();
        final Topic topic = new Topic(topicName);
        if (!topic.isValid()) {
            //LOG.debug("Drop connection because of invalid topic format");
            LOG.debug("Failed because of invalid topic format");
            //dropConnection();
            return;
        }
        switch (qos) {
            case AT_MOST_ONCE:
                postOffice.receivedPublishQos0(topic, username, clientId, payload, retain, msg);
                break;
            case AT_LEAST_ONCE: {
                final int messageID = msg.variableHeader().packetId();
                postOffice.receivedPublishQos1(this, topic, username, payload, messageID, retain, msg);
                break;
            }
            case EXACTLY_ONCE: {
                final int messageID = msg.variableHeader().packetId();
                final Session session = sessionRegistry.retrieve(clientId);
                session.receivedPublishQos2(messageID, msg);
                postOffice.receivedPublishQos2(this, msg, username);
                //                msg.release();
                break;
            }
            default:
                LOG.error("Unknown QoS-Type:{}", qos);
                break;
        }
    }

    @Override
    public void sendPublishReceived(int messageID) {
        //        LOG.trace("sendPubRec invoked on channel: {}", "IPCMQTTConnection");
        //        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.PUBREC, false, AT_MOST_ONCE, false, 0);
        //        MqttPubAckMessage pubRecMessage = new MqttPubAckMessage(fixedHeader, from(messageID));
        //        sendIfWritableElseDrop(pubRecMessage);
    }

    private void processPubRel(MqttMessage msg) {
        final Session session = sessionRegistry.retrieve(getClientId());
        final int messageID = ((MqttMessageIdVariableHeader) msg.variableHeader()).messageId();
        session.receivedPubRelQos2(messageID);
        sendPubCompMessage(messageID);
    }

    @Override
    public void sendPublish(MqttPublishMessage publishMsg) {
        final int packetId = publishMsg.variableHeader().packetId();
        final String topicName = publishMsg.variableHeader().topicName();
        final String clientId = getClientId();
        MqttQoS qos = publishMsg.fixedHeader().qosLevel();
        if (LOG.isTraceEnabled()) {
            LOG.trace("Sending PUBLISH({}) message. MessageId={}, CId={}, topic={}, payload={}", qos, packetId,
                clientId, topicName, DebugUtils.payload2Str(publishMsg.payload()));
        } else {
            LOG.debug("Sending PUBLISH({}) message. MessageId={}, CId={}, topic={}", qos, packetId, clientId,
                topicName);
        }
        //sendIfWritableElseDrop(publishMsg);
        try {
            ipcBridge.publishToIPC(publishMsg);
        } catch (IPCBridgeException e) {
            LOG.error("Error publishing to IPC", e);
        }
    }

    @Override
    public void sendIfWritableElseDrop(MqttMessage msg) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("OUT {} on channel {}", msg.fixedHeader().messageType(), "IPCMQTTConnection");
        }
        //        if (channel.isWritable()) {
        //            ChannelFuture channelFuture;
        //            if (brokerConfig.isImmediateBufferFlush()) {
        //                channelFuture = channel.writeAndFlush(msg);
        //            } else {
        //                channelFuture = channel.write(msg);
        //            }
        //            channelFuture.addListener(FIRE_EXCEPTION_ON_FAILURE);
        //        }
    }

    //    public void writabilityChanged() {
    //        //if (channel.isWritable())
    //        {
    //            LOG.debug("Channel {} is again writable", "IPCMQTTConnection");
    //            final Session session = sessionRegistry.retrieve(getClientId());
    //            session.writabilityChanged();
    //        }
    //    }

    @Override
    public boolean isWritable() {
        return true;
    }

    @Override
    public void sendPubAck(int messageID) {
        LOG.trace("sendPubAck invoked");
        //        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.PUBACK, false, AT_MOST_ONCE, false, 0);
        //        MqttPubAckMessage pubAckMessage = new MqttPubAckMessage(fixedHeader, from(messageID));
        //        sendIfWritableElseDrop(pubAckMessage);
    }

    private void sendPubCompMessage(int messageID) {
        LOG.trace("Sending PUBCOMP message on channel: {}, messageId: {}", "IPCMQTTConnection", messageID);
        //        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.PUBCOMP, false, AT_MOST_ONCE, false, 0);
        //        MqttMessage pubCompMessage = new MqttMessage(fixedHeader, from(messageID));
        //        sendIfWritableElseDrop(pubCompMessage);
    }

    @Override
    public String getClientId() {
        return this.clientId;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public void sendPublishRetainedQos0(Topic topic, MqttQoS qos, ByteBuf payload) {
        MqttPublishMessage publishMsg = retainedPublish(topic.toString(), qos, payload);
        sendPublish(publishMsg);
    }

    @Override
    public void sendPublishRetainedWithPacketId(Topic topic, MqttQoS qos, ByteBuf payload) {
        final int packetId = nextPacketId();
        MqttPublishMessage publishMsg = retainedPublishWithMessageId(topic.toString(), qos, payload, packetId);
        sendPublish(publishMsg);
    }

    private static MqttPublishMessage retainedPublish(String topic, MqttQoS qos, ByteBuf message) {
        return retainedPublishWithMessageId(topic, qos, message, 0);
    }

    private static MqttPublishMessage retainedPublishWithMessageId(String topic, MqttQoS qos, ByteBuf message,
                                                                   int messageId) {
        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.PUBLISH, false, qos, true, 0);
        MqttPublishVariableHeader varHeader = new MqttPublishVariableHeader(topic, messageId);
        return new MqttPublishMessage(fixedHeader, varHeader, message);
    }

    // TODO move this method in Session
    @Override
    public void sendPublishNotRetainedQos0(Topic topic, MqttQoS qos, ByteBuf payload) {
        MqttPublishMessage publishMsg = notRetainedPublish(topic.toString(), qos, payload);
        sendPublish(publishMsg);
    }

    static MqttPublishMessage notRetainedPublish(String topic, MqttQoS qos, ByteBuf message) {
        return notRetainedPublishWithMessageId(topic, qos, message, 0);
    }

    static MqttPublishMessage notRetainedPublishWithMessageId(String topic, MqttQoS qos, ByteBuf message,
                                                              int messageId) {
        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.PUBLISH, false, qos, false, 0);
        MqttPublishVariableHeader varHeader = new MqttPublishVariableHeader(topic, messageId);
        return new MqttPublishMessage(fixedHeader, varHeader, message);
    }

    @Override
    public int nextPacketId() {
        return lastPacketId.incrementAndGet();
    }

    @Override
    public String toString() {
        return "IPCMQTTConnection";
    }

    @Override
    public InetSocketAddress remoteAddress() {
        return InetSocketAddress.createUnresolved("fake.com", 0);
    }
}
