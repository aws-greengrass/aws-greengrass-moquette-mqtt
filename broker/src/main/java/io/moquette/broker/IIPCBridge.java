package io.moquette.broker;

import io.netty.handler.codec.mqtt.MqttPublishMessage;

public interface IIPCBridge {
    void publishToIPC(MqttPublishMessage publishMsg) throws IPCBridgeException;

    void subscribeToIPC(String topic);
}
