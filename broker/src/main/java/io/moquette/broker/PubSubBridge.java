package io.moquette.broker;

import io.netty.handler.codec.mqtt.MqttPublishMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PubSubBridge implements IGGBridge {

    private static final Logger LOG = LoggerFactory.getLogger(PubSubBridge.class);
    private GGMQTTConnection ggmqttConnection;

    public PubSubBridge(MQTTConnectionFactory mqttConnectionFactory) {
        ggmqttConnection = mqttConnectionFactory.createGGMQTTConnection(this);
    }

    public void start() {
        ggmqttConnection.connect(this.getClass().getSimpleName());
    }

    public void stop() {
        //Disconnect

    }

    @Override
    public void publishToGG(MqttPublishMessage publishMsg) {
        final int packetId = publishMsg.variableHeader().packetId();
        final String topicName = publishMsg.variableHeader().topicName();
        LOG.debug("Sending message to PubSub. MessageId={}, topic={}", packetId, topicName);

        // TODO: Publish to GG
    }
}
