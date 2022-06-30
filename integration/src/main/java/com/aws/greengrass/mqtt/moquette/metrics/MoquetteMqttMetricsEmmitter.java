/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette.metrics;

import com.aws.greengrass.telemetry.impl.Metric;
import com.aws.greengrass.telemetry.impl.MetricFactory;
import com.aws.greengrass.telemetry.models.TelemetryAggregation;
import com.aws.greengrass.telemetry.models.TelemetryUnit;
import io.moquette.interception.AbstractInterceptHandler;
import io.moquette.interception.InterceptHandler;
import io.moquette.interception.messages.InterceptConnectMessage;
import io.moquette.interception.messages.InterceptDisconnectMessage;
import io.moquette.interception.messages.InterceptPublishMessage;
import io.moquette.interception.messages.InterceptSubscribeMessage;
import io.moquette.interception.messages.InterceptUnsubscribeMessage;

import java.time.Instant;

public class MoquetteMqttMetricsEmmitter {

    private final MetricFactory metricFactory = new MetricFactory(MqttMetrics.MOQUETTE_MQTT_NAMESPACE);

    /**
     * Emits Moquette MQTT metrics.
     *
     * @param metric {@link Metric} to be emitted in Moquette MQTT namespace
     */
    public void emitMetric(Metric metric) {
        metricFactory.putMetricData(metric);
    }

    public class MqttMetricsCaptor extends AbstractInterceptHandler implements InterceptHandler {

        @Override
        public String getID() {
            return "MoquetteMqttMetricsCaptor";
        }

        @Override
        public void onConnect(InterceptConnectMessage msg) {
            emitMetric(Metric.builder()
                .namespace(MqttMetrics.MOQUETTE_MQTT_NAMESPACE)
                .name(MqttMetrics.CONNECT_SUCCESS)
                .unit(TelemetryUnit.Count)
                .aggregation(TelemetryAggregation.Sum)
                .value(1)
                .timestamp(Instant.now().toEpochMilli())
                .build());
        }

        @Override
        public void onDisconnect(InterceptDisconnectMessage msg) {
            emitMetric(Metric.builder()
                .namespace(MqttMetrics.MOQUETTE_MQTT_NAMESPACE)
                .name(MqttMetrics.DISCONNECT)
                .unit(TelemetryUnit.Count)
                .aggregation(TelemetryAggregation.Sum)
                .value(1)
                .timestamp(Instant.now().toEpochMilli())
                .build());
        }

        @Override
        public void onPublish(InterceptPublishMessage msg) {
            emitMetric(Metric.builder()
                .namespace(MqttMetrics.MOQUETTE_MQTT_NAMESPACE)
                .name(MqttMetrics.PUBLISH_OUT_SUCCESS)
                .unit(TelemetryUnit.Count)
                .aggregation(TelemetryAggregation.Sum)
                .value(1)
                .timestamp(Instant.now().toEpochMilli())
                .build());
        }

        @Override
        public void onSubscribe(InterceptSubscribeMessage msg) {
            emitMetric(Metric.builder()
                .namespace(MqttMetrics.MOQUETTE_MQTT_NAMESPACE)
                .name(MqttMetrics.SUBSCRIBE_SUCCESS)
                .unit(TelemetryUnit.Count)
                .aggregation(TelemetryAggregation.Sum)
                .value(1)
                .timestamp(Instant.now().toEpochMilli())
                .build());
        }

        @Override
        public void onUnsubscribe(InterceptUnsubscribeMessage msg) {
            emitMetric(Metric.builder()
                .namespace(MqttMetrics.MOQUETTE_MQTT_NAMESPACE)
                .name(MqttMetrics.UNSUBSCRIBE)
                .unit(TelemetryUnit.Count)
                .aggregation(TelemetryAggregation.Sum)
                .value(1)
                .timestamp(Instant.now().toEpochMilli())
                .build());
        }
    }
}
