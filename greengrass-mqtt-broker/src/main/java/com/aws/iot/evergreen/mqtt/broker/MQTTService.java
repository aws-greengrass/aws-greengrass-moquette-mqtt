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

        defaultConfig.setProperty(BrokerConstants.HOST_PROPERTY_NAME, "127.0.0.1");
        defaultConfig.setProperty(BrokerConstants.SSL_PORT_PROPERTY_NAME, "8883");

        defaultConfig.setProperty(BrokerConstants.JKS_PATH_PROPERTY_NAME, "serverstore.p12");
        defaultConfig.setProperty(BrokerConstants.KEY_STORE_TYPE, "pkcs12");
        defaultConfig.setProperty(BrokerConstants.KEY_STORE_PASSWORD_PROPERTY_NAME, "passw0rdsrv");
        defaultConfig.setProperty(BrokerConstants.KEY_MANAGER_PASSWORD_PROPERTY_NAME, "passw0rdsrv");

        defaultConfig.setProperty(BrokerConstants.ALLOW_ANONYMOUS_PROPERTY_NAME, "true");
        defaultConfig.setProperty(BrokerConstants.NEED_CLIENT_AUTH, "true");

        return defaultConfig;
    }
}
