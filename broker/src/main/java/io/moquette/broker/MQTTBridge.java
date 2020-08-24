package io.moquette.broker;

public class MQTTBridge {

    private PubSubBridge pubSubBridge;
    private IoTCoreBridge ioTCoreBridge;

    public MQTTBridge(MQTTConnectionFactory mqttConnectionFactory) {
        this.pubSubBridge = new PubSubBridge(mqttConnectionFactory);
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
