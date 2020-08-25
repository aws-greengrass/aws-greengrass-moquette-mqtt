package io.moquette.broker;

import io.netty.handler.codec.mqtt.MqttPublishMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IoTCoreBridge implements IGGBridge {

    private static final Logger LOG = LoggerFactory.getLogger(IoTCoreBridge.class);
    private GGMQTTConnection ggmqttConnection;

    public IoTCoreBridge(MQTTConnectionFactory mqttConnectionFactory) {
        ggmqttConnection = mqttConnectionFactory.createGGMQTTConnection(this);
    }

    public void start() {
        ggmqttConnection.connect(this.getClass().getSimpleName());
    }

    public void stop() {

    }

    @Override
    public void publishToGG(MqttPublishMessage publishMsg) {
        final int packetId = publishMsg.variableHeader().packetId();
        final String topicName = publishMsg.variableHeader().topicName();
        LOG.debug("Sending message to IoTCore proxy. MessageId={}, topic={}", packetId, topicName);

        // TODO: Publish to GG
    }
}
