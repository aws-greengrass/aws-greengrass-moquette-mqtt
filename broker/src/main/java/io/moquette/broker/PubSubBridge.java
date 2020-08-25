package io.moquette.broker;

import com.aws.iot.evergreen.builtin.services.pubsub.PubSubIPCAgent;
import com.aws.iot.evergreen.ipc.services.pubsub.MessagePublishedEvent;
import com.aws.iot.evergreen.ipc.services.pubsub.PubSubGenericResponse;
import com.aws.iot.evergreen.ipc.services.pubsub.PubSubPublishRequest;
import com.aws.iot.evergreen.ipc.services.pubsub.PubSubResponseStatus;
import com.aws.iot.evergreen.ipc.services.pubsub.PubSubSubscribeRequest;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.mqtt.MqttMessageBuilders;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.netty.handler.codec.mqtt.MqttQoS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Consumer;

public class PubSubBridge implements IIPCBridge {
    private static final boolean RETAINED = true;
    private static final Logger LOG = LoggerFactory.getLogger(PubSubBridge.class);
    private final IPCMQTTConnection ipcmqttConnection;

    private final PubSubIPCAgent pubSubAgent;

    public PubSubBridge(MQTTConnectionFactory mqttConnectionFactory, PubSubIPCAgent pubSubAgent) {
        ipcmqttConnection = mqttConnectionFactory.createIPCMQTTConnection(this);
        this.pubSubAgent = pubSubAgent;
    }

    public void start() {
        ipcmqttConnection.connect(this.getClass().getSimpleName());
    }

    public void stop() {
        //Disconnect

    }

    @Override
    public void publishToIPC(MqttPublishMessage publishMsg) throws IPCBridgeException {
        final int packetId = publishMsg.variableHeader().packetId();
        final String topicName = publishMsg.variableHeader().topicName();
        LOG.debug("Sending message to PubSub. MessageId={}, topic={}", packetId, topicName);

        ByteBuf payloadBuf = publishMsg.payload();
        byte[] payload = new byte[payloadBuf.readableBytes()];
        payloadBuf.readBytes(payload);

        PubSubPublishRequest publishRequest = PubSubPublishRequest.builder().topic(topicName).payload(payload).build();
        PubSubGenericResponse response = pubSubAgent.publish(publishRequest);
        if (response.getStatus() != PubSubResponseStatus.Success) {
            throw new IPCBridgeException("PubSub Publish didn't return SUCCESS");
        }
    }

    @Override
    public void subscribeToIPC(String topic) {
        PubSubSubscribeRequest subscribeRequest = PubSubSubscribeRequest.builder().topic(topic).build();

        Consumer<MessagePublishedEvent> forwardToMqtt = (message) -> {
            ByteBuf payload = Unpooled.wrappedBuffer(message.getPayload());
            MqttPublishMessage msgToPublish = MqttMessageBuilders.publish().payload(payload).qos(MqttQoS.AT_LEAST_ONCE)
                .retained(RETAINED).topicName(topic).build();
            ipcmqttConnection.handleMessage(msgToPublish);
        };

        pubSubAgent.subscribe(subscribeRequest, forwardToMqtt);
    }

}
