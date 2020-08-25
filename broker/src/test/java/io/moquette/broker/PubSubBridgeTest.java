package io.moquette.broker;

import com.aws.iot.evergreen.builtin.services.pubsub.PubSubIPCAgent;
import com.aws.iot.evergreen.ipc.services.pubsub.MessagePublishedEvent;
import com.aws.iot.evergreen.ipc.services.pubsub.PubSubPublishRequest;
import com.aws.iot.evergreen.ipc.services.pubsub.PubSubSubscribeRequest;
import com.aws.iot.evergreen.util.Pair;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.mqtt.MqttMessageBuilders;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.netty.handler.codec.mqtt.MqttQoS;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static com.aws.iot.evergreen.testcommons.testutilities.TestUtils.asyncAssertOnConsumer;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PubSubBridgeTest {
    private PubSubIPCAgent pubSubIPCAgent;

    private PubSubBridge bridge;

    private String testTopic;

    private String testPayload;

    @Mock
    private IPCMQTTConnection ipcmqttConnection;

    @Mock
    private MQTTConnectionFactory mqttConnectionFactory;

    @Before
    public void setup(){
        MockitoAnnotations.initMocks(this);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        pubSubIPCAgent = new PubSubIPCAgent(executor);
        when(mqttConnectionFactory.createIPCMQTTConnection(any())).thenReturn(ipcmqttConnection);
        bridge = new PubSubBridge(mqttConnectionFactory, pubSubIPCAgent);
        testTopic = "pubsub_data";
        testPayload = "some message";
    }

    @Test
    public void GIVEN_PubSubBridge_WHEN_called_publishToIPC_THEN_message_published() throws Exception {
        Pair<CompletableFuture<Void>, Consumer<MessagePublishedEvent>> cb = asyncAssertOnConsumer((m) -> {
            assertEquals(testPayload, new String(m.getPayload(), StandardCharsets.UTF_8));
            assertEquals(testTopic, m.getTopic());
        });
        PubSubSubscribeRequest subscribeRequest = PubSubSubscribeRequest.builder().topic(testTopic).build();
        pubSubIPCAgent.subscribe(subscribeRequest, cb.getRight());

        ByteBuf payload = Unpooled.wrappedBuffer(testPayload.getBytes(StandardCharsets.UTF_8));
        MqttPublishMessage mqttMessage = MqttMessageBuilders.publish().messageId(1).payload(payload)
            .qos(MqttQoS.AT_LEAST_ONCE).retained(true).topicName(testTopic).build();
        bridge.publishToIPC(mqttMessage);

        cb.getLeft().get(1, TimeUnit.SECONDS);
    }

    @Test
    public void GIVEN_PubSubBridge_WHEN_called_subscribeToIPC_THEN_message_received() throws Exception {
        bridge.subscribeToIPC(testTopic);

        PubSubPublishRequest publishRequest = PubSubPublishRequest.builder().topic(testTopic)
            .payload(testPayload.getBytes(StandardCharsets.UTF_8)).build();
        pubSubIPCAgent.publish(publishRequest);
        Thread.sleep(1000); //wait for message to be received by subscriber

        ArgumentCaptor<MqttPublishMessage> argument = ArgumentCaptor.forClass(MqttPublishMessage.class);
        verify(ipcmqttConnection).handleMessage(argument.capture());
        ByteBuf payloadBuf = argument.getValue().payload();
        byte[] actualPayload = new byte[payloadBuf.readableBytes()];
        payloadBuf.readBytes(actualPayload);
        assertEquals(testPayload, new String(actualPayload, StandardCharsets.UTF_8));
        assertEquals(testTopic, argument.getValue().variableHeader().topicName());
    }
}
