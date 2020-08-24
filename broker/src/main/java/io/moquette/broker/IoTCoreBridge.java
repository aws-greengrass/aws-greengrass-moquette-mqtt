package io.moquette.broker;

import io.netty.handler.codec.mqtt.MqttPublishMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.netty.handler.codec.mqtt.MqttQoS.AT_LEAST_ONCE;

public class IoTCoreBridge implements IIPCBridge {

    private static final Logger LOG = LoggerFactory.getLogger(IoTCoreBridge.class);
    private IPCMQTTConnection ipcmqttConnection;

    public IoTCoreBridge(MQTTConnectionFactory mqttConnectionFactory) {
        ipcmqttConnection = mqttConnectionFactory.createIPCMQTTConnection(this);
    }

    public void start() {
        ipcmqttConnection.connect(this.getClass().getSimpleName());
        ipcmqttConnection.subscribe("#", AT_LEAST_ONCE);
    }

    public void stop() {

    }

    @Override
    public void publishToIPC(MqttPublishMessage publishMsg) {
        final int packetId = publishMsg.variableHeader().packetId();
        final String topicName = publishMsg.variableHeader().topicName();
        LOG.debug("Sending message to IoTCore proxy. MessageId={}, topic={}", packetId, topicName);

        // TODO: Publish to IPC
    }
}
