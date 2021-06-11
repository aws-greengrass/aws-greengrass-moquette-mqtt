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

import static io.moquette.BrokerConstants.FLIGHT_BEFORE_RESEND_MS;
import static io.moquette.BrokerConstants.INFLIGHT_WINDOW_SIZE;
import io.moquette.broker.SessionRegistry.EnqueuedMessage;
import io.moquette.broker.SessionRegistry.PublishedMessage;
import io.moquette.broker.subscriptions.Subscription;
import io.moquette.broker.subscriptions.Topic;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.mqtt.*;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

class Session {

    private static final Logger LOG = LoggerFactory.getLogger(Session.class);

    static class InFlightPacket implements Delayed {

        final int packetId;
        private long startTime;

        InFlightPacket(int packetId, long delayInMilliseconds) {
            this.packetId = packetId;
            this.startTime = System.currentTimeMillis() + delayInMilliseconds;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            long diff = startTime - System.currentTimeMillis();
            return unit.convert(diff, TimeUnit.MILLISECONDS);
        }

        @Override
        public int compareTo(Delayed o) {
            if ((this.startTime - ((InFlightPacket) o).startTime) == 0) {
                return 0;
            }
            if ((this.startTime - ((InFlightPacket) o).startTime) > 0) {
                return 1;
            } else {
                return -1;
            }
        }
    }

    enum SessionStatus {
        CONNECTED, CONNECTING, DISCONNECTING, DISCONNECTED
    }

    static final class Will {

        final String topic;
        final ByteBuf payload;
        final MqttQoS qos;
        final boolean retained;

        Will(String topic, ByteBuf payload, MqttQoS qos, boolean retained) {
            this.topic = topic;
            this.payload = payload;
            this.qos = qos;
            this.retained = retained;
        }
    }

    private final String clientId;
    private boolean clean;
    private Will will;
    private final Queue<SessionRegistry.EnqueuedMessage> sessionQueue;
    private final AtomicReference<SessionStatus> status = new AtomicReference<>(SessionStatus.DISCONNECTED);
    private MQTTConnection mqttConnection;
    private List<Subscription> subscriptions = new ArrayList<>();
    private final Map<Integer, SessionRegistry.EnqueuedMessage> inflightWindow = new HashMap<>();
    private final DelayQueue<InFlightPacket> inflightTimeouts = new DelayQueue<>();
    private final Map<Integer, MqttPublishMessage> qos2Receiving = new HashMap<>();
    private final AtomicInteger inflightSlots = new AtomicInteger(INFLIGHT_WINDOW_SIZE); // this should be configurable

    Session(String clientId, boolean clean, Will will, Queue<SessionRegistry.EnqueuedMessage> sessionQueue) {
        this(clientId, clean, sessionQueue);
        this.will = will;
    }

    Session(String clientId, boolean clean, Queue<SessionRegistry.EnqueuedMessage> sessionQueue) {
        if (sessionQueue == null) {
            throw new IllegalArgumentException("sessionQueue parameter can't be null");
        }
        this.clientId = clientId;
        this.clean = clean;
        this.sessionQueue = sessionQueue;
    }

    void update(boolean clean, Will will) {
        this.clean = clean;
        this.will = will;
    }

    void markConnecting() {
        assignState(SessionStatus.DISCONNECTED, SessionStatus.CONNECTING);
    }

    boolean completeConnection() {
        return assignState(Session.SessionStatus.CONNECTING, Session.SessionStatus.CONNECTED);
    }

    void bind(MQTTConnection mqttConnection) {
        this.mqttConnection = mqttConnection;
    }

    public boolean disconnected() {
        return status.get() == SessionStatus.DISCONNECTED;
    }

    public boolean connected() {
        return status.get() == SessionStatus.CONNECTED;
    }

    public String getClientID() {
        return clientId;
    }

    public List<Subscription> getSubscriptions() {
        return new ArrayList<>(subscriptions);
    }

    public void addSubscriptions(List<Subscription> newSubscriptions) {
        subscriptions.addAll(newSubscriptions);
    }

    public boolean hasWill() {
        return will != null;
    }

    public Will getWill() {
        return will;
    }

    boolean assignState(SessionStatus expected, SessionStatus newState) {
        return status.compareAndSet(expected, newState);
    }

    public void closeImmediately() {
        mqttConnection.dropConnection();
    }

    public void disconnect() {
        final boolean res = assignState(SessionStatus.CONNECTED, SessionStatus.DISCONNECTING);
        if (!res) {
            // someone already moved away from CONNECTED
            // TODO what to do?
            return;
        }

        mqttConnection = null;
        will = null;

        assignState(SessionStatus.DISCONNECTING, SessionStatus.DISCONNECTED);
    }

    boolean isClean() {
        return clean;
    }

    public void processPubRec(int packetId) {
        // Message discarded, make sure any buffers in it are released
        SessionRegistry.EnqueuedMessage removed = inflightWindow.remove(packetId);
        if (removed != null) {
            removed.release();
        }

        inflightSlots.incrementAndGet();
        if (canSkipQueue()) {
            inflightSlots.decrementAndGet();
            int pubRelPacketId = packetId/*mqttConnection.nextPacketId()*/;
            inflightWindow.put(pubRelPacketId, new SessionRegistry.PubRelMarker());
            inflightTimeouts.add(new InFlightPacket(pubRelPacketId, FLIGHT_BEFORE_RESEND_MS));
            MqttMessage pubRel = MQTTConnection.pubrel(pubRelPacketId);
            mqttConnection.sendIfWritableElseDrop(pubRel);

            drainQueueToConnection();
        } else {
            sessionQueue.add(new SessionRegistry.PubRelMarker());
        }
    }

    public void processPubComp(int messageID) {
        // Message discarded, make sure any buffers in it are released
        SessionRegistry.EnqueuedMessage removed = inflightWindow.remove(messageID);
        if (removed != null) {
            removed.release();
        }

        inflightSlots.incrementAndGet();

        drainQueueToConnection();

        // TODO notify the interceptor
//                final InterceptAcknowledgedMessage interceptAckMsg = new InterceptAcknowledgedMessage(inflightMsg,
// topic, username, messageID);
//                m_interceptor.notifyMessageAcknowledged(interceptAckMsg);
    }

    public void sendPublishOnSessionAtQos(Topic topic, MqttQoS qos, ByteBuf payload) {
        switch (qos) {
            case AT_MOST_ONCE:
                if (connected()) {
                    mqttConnection.sendPublishNotRetainedQos0(topic, qos, payload);
                }
                break;
            case AT_LEAST_ONCE:
                sendPublishQos1(topic, qos, payload);
                break;
            case EXACTLY_ONCE:
                sendPublishQos2(topic, qos, payload);
                break;
            case FAILURE:
                LOG.error("Not admissible");
        }
    }

    private void sendPublishQos1(Topic topic, MqttQoS qos, ByteBuf payload) {
        if (!connected() && isClean()) {
            //pushing messages to disconnected not clean session
            return;
        }

        if (canSkipQueue()) {
            inflightSlots.decrementAndGet();
            int packetId = mqttConnection.nextPacketId();

            // Adding to a map, retain.
            payload.retain();
            EnqueuedMessage old = inflightWindow.put(packetId, new PublishedMessage(topic, qos, payload));
            // If there already was something, release it.
            if (old != null) {
                old.release();
                inflightSlots.incrementAndGet();
            }
            inflightTimeouts.add(new InFlightPacket(packetId, FLIGHT_BEFORE_RESEND_MS));

            MqttPublishMessage publishMsg = MQTTConnection.notRetainedPublishWithMessageId(topic.toString(), qos,
                                                                                           payload, packetId);
            mqttConnection.sendPublish(publishMsg);

            // TODO drainQueueToConnection();?
        } else {
            queueOrDisconnect(topic, qos, payload);
        }
    }

    private void sendPublishQos2(Topic topic, MqttQoS qos, ByteBuf payload) {
        if (canSkipQueue()) {
            inflightSlots.decrementAndGet();
            int packetId = mqttConnection.nextPacketId();

            // Retain before adding to map
            payload.retain();
            EnqueuedMessage old = inflightWindow.put(packetId, new SessionRegistry.PublishedMessage(topic, qos, payload));
            // If there already was something, release it.
            if (old != null) {
                old.release();
                inflightSlots.incrementAndGet();
            }
            inflightTimeouts.add(new InFlightPacket(packetId, FLIGHT_BEFORE_RESEND_MS));

            MqttPublishMessage publishMsg = MQTTConnection.notRetainedPublishWithMessageId(topic.toString(), qos,
                                                                                           payload, packetId);
            mqttConnection.sendPublish(publishMsg);

            drainQueueToConnection();
        } else {
            queueOrDisconnect(topic, qos, payload);
        }
    }

    private void queueOrDisconnect(Topic topic, MqttQoS qos, ByteBuf payload) {
        final SessionRegistry.PublishedMessage msg = new SessionRegistry.PublishedMessage(topic, qos, payload);
        try {
            msg.retain();
            sessionQueue.add(msg);
        } catch (IllegalStateException e) {
            LOG.warn("Max queue size exceeded! Draining queue and disconnecting client.");
            msg.release();
            closeImmediately();
            drainQueuedAndInflightMessages();
        }
    }

    private boolean canSkipQueue() {
        return sessionQueue.isEmpty() &&
            inflightSlots.get() > 0 &&
            connected() &&
            mqttConnection.channel.isWritable();
    }

    private boolean inflighHasSlotsAndConnectionIsUp() {
        return inflightSlots.get() > 0 &&
            connected() &&
            mqttConnection.channel.isWritable();
    }

    void pubAckReceived(int ackPacketId) {
        // TODO remain to invoke in somehow m_interceptor.notifyMessageAcknowledged
        SessionRegistry.EnqueuedMessage removed = inflightWindow.remove(ackPacketId);
        if (removed != null) {
            removed.release();
        }

        inflightSlots.incrementAndGet();
        drainQueueToConnection();
    }

    public void flushAllQueuedMessages() {
        drainQueueToConnection();
    }

    public void resendInflightNotAcked() {
        Collection<InFlightPacket> expired = new ArrayList<>(INFLIGHT_WINDOW_SIZE);
        inflightTimeouts.drainTo(expired);

        debugLogPacketIds(expired);

        for (InFlightPacket notAckPacketId : expired) {
            final SessionRegistry.PublishedMessage msg =
                (SessionRegistry.PublishedMessage) inflightWindow.get(notAckPacketId.packetId);
            if (msg == null) {
                // Already acked...
                continue;
            }
            final Topic topic = msg.topic;
            final MqttQoS qos = msg.publishingQos;
            final ByteBuf payload = msg.payload;
            final ByteBuf copiedPayload = payload.retainedDuplicate();
            MqttPublishMessage publishMsg = publishNotRetainedDuplicated(notAckPacketId, topic, qos, copiedPayload);
            inflightTimeouts.add(new InFlightPacket(notAckPacketId.packetId, FLIGHT_BEFORE_RESEND_MS));
            mqttConnection.sendPublish(publishMsg);
        }
    }

    private void debugLogPacketIds(Collection<InFlightPacket> expired) {
        if (!LOG.isDebugEnabled() || expired.isEmpty()) {
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (InFlightPacket packet : expired) {
            sb.append(packet.packetId).append(", ");
        }
        LOG.debug("Resending {} in flight packets [{}]", expired.size(), sb);
    }

    private MqttPublishMessage publishNotRetainedDuplicated(InFlightPacket notAckPacketId, Topic topic, MqttQoS qos,
                                                            ByteBuf payload) {
        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.PUBLISH, true, qos, false, 0);
        MqttPublishVariableHeader varHeader = new MqttPublishVariableHeader(topic.toString(), notAckPacketId.packetId);
        return new MqttPublishMessage(fixedHeader, varHeader, payload);
    }

    private void drainQueueToConnection() {
        // consume the queue
        while (!sessionQueue.isEmpty() && inflighHasSlotsAndConnectionIsUp()) {
            final SessionRegistry.EnqueuedMessage msg = sessionQueue.remove();
            inflightSlots.decrementAndGet();
            int sendPacketId = mqttConnection.nextPacketId();

            // Putting it in a map, but the retain is cancelled out by the below release.
            EnqueuedMessage old = inflightWindow.put(sendPacketId, msg);
            if (old != null) {
                old.release();
                inflightSlots.incrementAndGet();
            }
            if (msg instanceof SessionRegistry.PubRelMarker) {
                MqttMessage pubRel = MQTTConnection.pubrel(sendPacketId);
                mqttConnection.sendIfWritableElseDrop(pubRel);
            } else {
                final SessionRegistry.PublishedMessage msgPub = (SessionRegistry.PublishedMessage) msg;
                MqttPublishMessage publishMsg = MQTTConnection.notRetainedPublishWithMessageId(msgPub.topic.toString(),
                    msgPub.publishingQos,
                    msgPub.payload, sendPacketId);
                mqttConnection.sendPublish(publishMsg);
            }
            // we fetched msg from a map, but the release is cancelled out by the above retain
        }
    }

    public void drainQueuedAndInflightMessages() {
        while (!sessionQueue.isEmpty()) {
            final SessionRegistry.EnqueuedMessage msg = sessionQueue.remove();
            msg.release();
        }
        inflightWindow.forEach((k, v) -> {
            if (inflightWindow.remove(k) == v) {
                v.release();
                inflightSlots.incrementAndGet();
            }
        });
    }

    public void writabilityChanged() {
        drainQueueToConnection();
    }

    public void sendQueuedMessagesWhileOffline() {
        LOG.trace("Republishing all saved messages for session {}", this);
        drainQueueToConnection();
    }

    void sendRetainedPublishOnSessionAtQos(Topic topic, MqttQoS qos, ByteBuf payload) {
        if (qos != MqttQoS.AT_MOST_ONCE) {
            // QoS 1 or 2
            mqttConnection.sendPublishRetainedWithPacketId(topic, qos, payload);
        } else {
            mqttConnection.sendPublishRetainedQos0(topic, qos, payload);
        }
    }

    public void receivedPublishQos2(int messageID, MqttPublishMessage msg) {
        // Retain before putting msg in map.
        ReferenceCountUtil.retain(msg);

        MqttPublishMessage old = qos2Receiving.put(messageID, msg);
        // In case of evil client with duplicate msgid.
        ReferenceCountUtil.release(old);

        mqttConnection.sendPublishReceived(messageID);
    }

    public void receivedPubRelQos2(int messageID) {
        // Done with the message, remove from queue and release payload.
        final MqttPublishMessage removedMsg = qos2Receiving.remove(messageID);
        ReferenceCountUtil.release(removedMsg);
    }

    Optional<InetSocketAddress> remoteAddress() {
        if (connected()) {
            return Optional.of(mqttConnection.remoteAddress());
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return "Session{" +
            "clientId='" + clientId + '\'' +
            ", clean=" + clean +
            ", status=" + status +
            ", inflightSlots=" + inflightSlots +
            '}';
    }
}
