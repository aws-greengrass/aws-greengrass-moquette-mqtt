/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */

package com.aws.iot.evergreen.mqtt.broker;

import com.aws.iot.evergreen.config.Topics;
import com.aws.iot.evergreen.dependency.ImplementsService;
import com.aws.iot.evergreen.dependency.State;
import com.aws.iot.evergreen.kernel.EvergreenService;

import io.moquette.BrokerConstants;
import io.moquette.broker.Server;
import io.moquette.broker.config.IConfig;
import io.moquette.broker.config.MemoryConfig;

import javax.inject.Inject;
import java.io.IOException;
import java.util.Properties;

@ImplementsService(name = MQTTService.SERVICE_NAME, autostart = true)
public class MQTTService extends EvergreenService {
    public static final String SERVICE_NAME = "aws.greengrass.mqtt";
    private final Server mqttBroker = new Server();

    /**
     * Constructor for EvergreenService.
     *
     * @param topics Root Configuration topic for this service
     */
    @Inject
    public MQTTService(Topics topics) {
        super(topics);
    }

    @Override
    public void startup() {
        try {
            mqttBroker.startServer(getDefaultConfig());
        } catch (IOException e) {
            serviceErrored(e);
            return;
        }
        reportState(State.RUNNING);
    }

    @Override
    public void shutdown() {
        mqttBroker.stopServer();
    }

    public IConfig getDefaultConfig() {
        // TODO: Enable SSL, get certs from DCM
        IConfig defaultConfig = new MemoryConfig(new Properties());
        defaultConfig.setProperty(BrokerConstants.PORT_PROPERTY_NAME, "8883");
        return defaultConfig;
    }
}
