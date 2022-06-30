/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.mqtt.moquette.metrics;


public final class MqttMetrics {
    public static final String MOQUETTE_MQTT_NAMESPACE = "MoquetteMqtt";
    public static final String CONNECT_SUCCESS = "Connect.Success";
    public static final String CONNECT_AUTH_ERROR = "Connect.AuthError";
    public static final String SUBSCRIBE_SUCCESS = "Subscribe.Success";
    public static final String SUBSCRIBE_AUTH_ERROR = "Subscribe.AuthError";
    public static final String PUBLISH_OUT_SUCCESS = "PublishOut.Success";
    public static final String PUBLISH_IN_AUTH_ERROR = "PublishIn.AuthError";
    public static final String DISCONNECT = "Disconnect";
    public static final String UNSUBSCRIBE = "Unsubscribe";
    public static final String UNKNOWN_AUTH_ERROR = "UnknownAuthError";
}
