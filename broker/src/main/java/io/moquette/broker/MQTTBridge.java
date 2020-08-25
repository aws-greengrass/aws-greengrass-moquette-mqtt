package io.moquette.broker;

import com.aws.iot.evergreen.builtin.services.pubsub.PubSubIPCAgent;

public class MQTTBridge {

    private PubSubBridge pubSubBridge;
    private IoTCoreBridge ioTCoreBridge;

    public MQTTBridge(MQTTConnectionFactory mqttConnectionFactory, PubSubIPCAgent pubSubIPCAgent) {
        this.pubSubBridge = new PubSubBridge(mqttConnectionFactory, pubSubIPCAgent);
        this.ioTCoreBridge = new IoTCoreBridge(mqttConnectionFactory);
    }

    public void start() {
        pubSubBridge.start();
        ioTCoreBridge.start();
    }

    public void stop() {
        pubSubBridge.stop();
        ioTCoreBridge.stop();
    }
}
