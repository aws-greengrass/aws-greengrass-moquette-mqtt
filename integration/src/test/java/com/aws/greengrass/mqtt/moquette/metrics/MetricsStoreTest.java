/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette.metrics;

import com.aws.greengrass.mqtt.moquette.metrics.MetricsStore.MqttMetric;
import com.aws.greengrass.telemetry.impl.Metric;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalToObject;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class MetricsStoreTest {

    private final MetricsStore metricsStore = MetricsStore.getInstance();

    @AfterEach
    void reset() {
        metricsStore.getAndResetTelemetryMetrics();
    }

    @Test
    void GIVEN_MetricsStore_WHEN_getInstance_THEN_returnsSingletonMetricsStore() {
        MetricsStore anotherStoreRef = MetricsStore.getInstance();
        assertThat(anotherStoreRef, is(notNullValue()));
        assertThat(anotherStoreRef, equalToObject(metricsStore));
    }

    @Test
    void GIVEN_MetricsStore_WHEN_incrementMetric_and_getAndResetTelemetryMetrics_THEN_returnsUpdatedTelemetryMetric_and_reset_store() {
        // verify that the metrics are initialized with zero value
        Map<MqttMetric, AtomicInteger> metrics = metricsStore.getMetrics();
        assertThat(metrics.get(MqttMetric.CONNECT_SUCCESS).get(), is(0));

        // verify the metrics value increment
        metricsStore.incrementMetricValue(MqttMetric.CONNECT_SUCCESS);
        List<Metric> telemetryMetrics = metricsStore.getAndResetTelemetryMetrics();
        Metric connectSuccessMetric =
            lookupTelemetryMetricByName(telemetryMetrics, MqttMetric.CONNECT_SUCCESS.toString()).get();
        assertThat(connectSuccessMetric, is(notNullValue()));
        assertThat(connectSuccessMetric.getValue(), is(1));

        // verify metrics are reset to zero after last getAndResetTelemetryMetrics call
        int newConnectSuccessMetricValue = metricsStore.getMetrics().get(MqttMetric.CONNECT_SUCCESS).get();
        assertThat(newConnectSuccessMetricValue, is(0));
    }

    private Optional<Metric> lookupTelemetryMetricByName(List<Metric> telemetryMetrics, String name) {
        return telemetryMetrics.stream().filter(metric -> metric.getName().equals(name)).findAny();
    }
}
