package io.moquette.broker;

import io.moquette.broker.subscriptions.Topic;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.mqtt.MqttMessage;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.netty.handler.codec.mqtt.MqttQoS;
import io.netty.handler.codec.mqtt.MqttSubAckMessage;

import java.net.InetSocketAddress;
import java.util.List;

public interface IMQTTConnection {
    void dropConnection();
    void sendIfWritableElseDrop(MqttMessage msg);
    void sendPublishNotRetainedQos0(Topic topic, MqttQoS qos, ByteBuf payload);
    int nextPacketId();
    void sendPublish(MqttPublishMessage publishMsg);
    void sendPublishRetainedWithPacketId(Topic topic, MqttQoS qos, ByteBuf payload);
    void sendPublishRetainedQos0(Topic topic, MqttQoS qos, ByteBuf payload);
    void sendPublishReceived(int messageID);
    InetSocketAddress remoteAddress();
    boolean isWritable();
    void sendSubAckMessage(int messageID, MqttSubAckMessage ackMessage);
    void sendConnAck(boolean isSessionAlreadyPresent);
    String getUsername();
    String getClientId();
    void sendUnsubAckMessage(List<String> topics, String clientID, int messageID);
    void sendPubAck(int messageID);
}
