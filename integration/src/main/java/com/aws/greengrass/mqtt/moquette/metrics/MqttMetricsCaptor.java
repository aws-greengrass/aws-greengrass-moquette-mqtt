/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette.metrics;

import com.aws.greengrass.mqtt.moquette.metrics.MetricsStore.MqttMetric;
import io.moquette.interception.AbstractInterceptHandler;
import io.moquette.interception.InterceptHandler;
import io.moquette.interception.messages.InterceptConnectMessage;
import io.moquette.interception.messages.InterceptDisconnectMessage;
import io.moquette.interception.messages.InterceptPublishMessage;
import io.moquette.interception.messages.InterceptSubscribeMessage;
import io.moquette.interception.messages.InterceptUnsubscribeMessage;


public class MqttMetricsCaptor extends AbstractInterceptHandler implements InterceptHandler {

    @Override
    public String getID() {
        return "MoquetteMqttMetricsCaptor";
    }

    @Override
    public void onConnect(InterceptConnectMessage msg) {
        MetricsStore.getInstance().incrementMetricValue(MqttMetric.CONNECT_SUCCESS);
    }

    @Override
    public void onDisconnect(InterceptDisconnectMessage msg) {
        MetricsStore.getInstance().incrementMetricValue(MqttMetric.DISCONNECT);
    }

    @Override
    public void onPublish(InterceptPublishMessage msg) {
        MetricsStore.getInstance().incrementMetricValue(MqttMetric.PUBLISH_OUT_SUCCESS);
    }

    @Override
    public void onSubscribe(InterceptSubscribeMessage msg) {
        MetricsStore.getInstance().incrementMetricValue(MqttMetric.SUBSCRIBE_SUCCESS);
    }

    @Override
    public void onUnsubscribe(InterceptUnsubscribeMessage msg) {
        MetricsStore.getInstance().incrementMetricValue(MqttMetric.UNSUBSCRIBE);
    }
}
