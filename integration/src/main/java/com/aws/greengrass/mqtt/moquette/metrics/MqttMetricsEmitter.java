/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette.metrics;

import com.aws.greengrass.telemetry.impl.Metric;
import com.aws.greengrass.telemetry.impl.MetricFactory;

import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

public class MqttMetricsEmitter {
    private static final long DEFAULT_METRIC_EMIT_FREQUENCY_SECONDS = 30;

    private final ScheduledExecutorService ses;
    private final MetricFactory metricFactory = new MetricFactory(MetricsStore.LOCAL_MQTT_NAMESPACE);

    private ScheduledFuture<?> emitFuture;

    /**
     * Constructor.
     *
     * @param ses ScheduledExecutorService for periodic metric emission
     */
    @Inject
    public MqttMetricsEmitter(ScheduledExecutorService ses) {
        this.ses = ses;
    }

    /**
     * Schedules periodic MQTT metric emission.
     */
    public void schedulePeriodicMetricEmit() {
        if (emitFuture != null) {
            emitFuture.cancel(true);
        }

        emitFuture = ses.scheduleAtFixedRate(this::emitMetrics, DEFAULT_METRIC_EMIT_FREQUENCY_SECONDS,
            DEFAULT_METRIC_EMIT_FREQUENCY_SECONDS, TimeUnit.SECONDS);
    }

    private void emitMetrics() {
        List<Metric> metrics = MetricsStore.getInstance().getAndResetTelemetryMetrics();
        metrics.forEach(metricFactory::putMetricData);
    }

}
