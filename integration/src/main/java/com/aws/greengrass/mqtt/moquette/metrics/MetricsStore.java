/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette.metrics;


import com.aws.greengrass.telemetry.impl.Metric;
import com.aws.greengrass.telemetry.models.TelemetryAggregation;
import com.aws.greengrass.telemetry.models.TelemetryUnit;
import lombok.AccessLevel;
import lombok.Getter;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class MetricsStore {
    public static final String LOCAL_MQTT_NAMESPACE = "LocalMQTT";
    @Getter(AccessLevel.PACKAGE)
    private final Map<MqttMetric, AtomicInteger> metrics = new HashMap<>();

    private MetricsStore() {
        init();
    }

    private static class MetricsStoreHelper {
        @SuppressWarnings("PMD.AccessorClassGeneration")
        private static final MetricsStore INSTANCE = new MetricsStore();
    }

    /**
     * Gets the singleton instance of MetricsStore with lazy initialization.
     *
     * @return {@link MetricsStore}
     */
    public static MetricsStore getInstance() {
        return MetricsStoreHelper.INSTANCE;
    }

    public void incrementMetricValue(MqttMetric metric) {
        Optional.ofNullable(metrics.get(metric)).map(AtomicInteger::incrementAndGet);
    }

    public List<Metric> getAndResetTelemetryMetrics() {
        return metrics.keySet().stream().map(this::getTelemetryMetricAndReset)
            .collect(Collectors.toList());
    }

    private Metric getTelemetryMetricAndReset(MqttMetric metric) {
        int metricValue = metrics.get(metric).getAndSet(0);
        return Metric.builder()
            .namespace(LOCAL_MQTT_NAMESPACE)
            .name(metric.toString())
            .unit(TelemetryUnit.Count)
            .aggregation(TelemetryAggregation.Sum)
            .value(metricValue)
            .timestamp(Instant.now().toEpochMilli())
            .build();
    }

    private void init() {
        metrics.put(MqttMetric.CONNECT_SUCCESS, new AtomicInteger(0));
        metrics.put(MqttMetric.CONNECT_AUTH_ERROR, new AtomicInteger(0));
        metrics.put(MqttMetric.SUBSCRIBE_SUCCESS, new AtomicInteger(0));
        metrics.put(MqttMetric.SUBSCRIBE_AUTH_ERROR, new AtomicInteger(0));
        metrics.put(MqttMetric.PUBLISH_OUT_SUCCESS, new AtomicInteger(0));
        metrics.put(MqttMetric.PUBLISH_IN_AUTH_ERROR, new AtomicInteger(0));
        metrics.put(MqttMetric.UNSUBSCRIBE, new AtomicInteger(0));
        metrics.put(MqttMetric.DISCONNECT, new AtomicInteger(0));
        metrics.put(MqttMetric.UNKNOWN_AUTH_ERROR, new AtomicInteger(0));
    }

    public enum MqttMetric {
        CONNECT_SUCCESS("Connect.Success"),
        CONNECT_AUTH_ERROR("Connect.AuthError"),
        SUBSCRIBE_SUCCESS("Subscribe.Success"),
        SUBSCRIBE_AUTH_ERROR("Subscribe.AuthError"),
        PUBLISH_OUT_SUCCESS("PublishOut.Success"),
        PUBLISH_IN_AUTH_ERROR("PublishIn.AuthError"),
        DISCONNECT("Disconnect"),
        UNSUBSCRIBE("Unsubscribe"),
        UNKNOWN_AUTH_ERROR("UnknownAuthError");

        private final String name;
        MqttMetric(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
