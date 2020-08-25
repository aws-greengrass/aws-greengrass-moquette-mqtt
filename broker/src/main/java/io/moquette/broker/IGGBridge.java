package io.moquette.broker;

import io.netty.handler.codec.mqtt.MqttPublishMessage;

public interface IGGBridge {
    void publishToGG(MqttPublishMessage publishMsg);
}
