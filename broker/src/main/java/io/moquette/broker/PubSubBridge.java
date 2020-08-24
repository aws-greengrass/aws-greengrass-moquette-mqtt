package io.moquette.broker;

import io.netty.handler.codec.mqtt.MqttPublishMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PubSubBridge implements IIPCBridge {

    private static final Logger LOG = LoggerFactory.getLogger(PubSubBridge.class);
    private IPCMQTTConnection ipcmqttConnection;

    public PubSubBridge(MQTTConnectionFactory mqttConnectionFactory) {
        ipcmqttConnection = mqttConnectionFactory.createIPCMQTTConnection(this);
    }

    public void start() {
        ipcmqttConnection.connect(this.getClass().getSimpleName());
    }

    public void stop() {
        //Disconnect

    }

    @Override
    public void publishToIPC(MqttPublishMessage publishMsg) {
        final int packetId = publishMsg.variableHeader().packetId();
        final String topicName = publishMsg.variableHeader().topicName();
        LOG.debug("Sending message to PubSub. MessageId={}, topic={}", packetId, topicName);

        // TODO: Publish to IPC
    }
}
