/*
 * Copyright (c) 2012-2018 The original author or authors
 * ------------------------------------------------------
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.moquette.integration;

import io.moquette.broker.Server;
import io.moquette.broker.config.IConfig;
import io.moquette.broker.config.MemoryConfig;
import org.awaitility.Awaitility;
import org.awaitility.Durations;
import org.eclipse.paho.client.mqttv3.IMqttClient;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ServerIntegrationQoSValidationTest {

    private static final Logger LOG = LoggerFactory.getLogger(ServerIntegrationQoSValidationTest.class);

    Server m_server;

    IMqttClient m_subscriber;
    IMqttClient m_publisher;
    MessageCollector m_callback;
    IConfig m_config;

    @TempDir
    Path tempFolder;

    protected void startServer(String dbPath) throws IOException {
        m_server = new Server();
        final Properties configProps = IntegrationUtils.prepareTestProperties(dbPath);
        m_config = new MemoryConfig(configProps);
        m_server.startServer(m_config);
    }

    @BeforeAll
    public static void beforeTests() {
        Awaitility.setDefaultTimeout(Durations.ONE_SECOND);
    }

    @BeforeEach
    public void setUp() throws Exception {
        String dbPath = IntegrationUtils.tempH2Path(tempFolder);
        startServer(dbPath);

        m_subscriber = new MqttClient("tcp://localhost:1883", "Subscriber", new MemoryPersistence());
        m_callback = new MessageCollector();
        m_subscriber.setCallback(m_callback);
        m_subscriber.connect();

        m_publisher = new MqttClient("tcp://localhost:1883", "Publisher", new MemoryPersistence());
        m_publisher.connect();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (m_publisher.isConnected()) {
            m_publisher.disconnect();
        }

        if (m_subscriber.isConnected()) {
            m_subscriber.disconnect();
        }

        m_server.stopServer();
    }

    @Test
    public void checkSubscriberQoS0ReceiveQoS0publishes() throws Exception {
        LOG.info("*** checkSubscriberQoS0ReceiveQoS0publishes ***");
        m_subscriber.subscribe("/topic", 0);

        m_publisher.publish("/topic", "Hello world MQTT QoS0".getBytes(UTF_8), 0, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS0", message.toString());
        assertEquals(0, message.getQos());
    }

    @Test
    public void checkSubscriberQoS0ReceiveQoS1publishes_downgrade() throws Exception {
        LOG.info("*** checkSubscriberQoS0ReceiveQoS1publishes_downgrade ***");
        m_subscriber.subscribe("/topic", 0);

        m_publisher.publish("/topic", "Hello world MQTT QoS1".getBytes(UTF_8), 1, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS1", message.toString());
        assertEquals(0, message.getQos());
    }

    @Test
    public void checkSubscriberQoS0ReceiveQoS2publishes_downgrade() throws Exception {
        LOG.info("*** checkSubscriberQoS0ReceiveQoS2publishes_downgrade ***");
        m_subscriber.subscribe("/topic", 0);

        m_publisher.publish("/topic", "Hello world MQTT QoS2".getBytes(UTF_8), 2, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS2", message.toString());
        assertEquals(0, message.getQos());
    }

    @Test
    public void checkSubscriberQoS1ReceiveQoS0publishes() throws Exception {
        LOG.info("*** checkSubscriberQoS1ReceiveQoS0publishes ***");
        m_subscriber.subscribe("/topic", 1);

        m_publisher.publish("/topic", "Hello world MQTT QoS0".getBytes(UTF_8), 0, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS0", message.toString());
        assertEquals(0, message.getQos());
    }

    @Test
    public void checkSubscriberQoS1ReceiveQoS1publishes() throws Exception {
        LOG.info("*** checkSubscriberQoS1ReceiveQoS1publishes ***");
        m_subscriber.subscribe("/topic", 1);

        m_publisher.publish("/topic", "Hello world MQTT QoS1".getBytes(UTF_8), 1, false);
        Awaitility.await().atMost(5, TimeUnit.SECONDS)
            .until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS1", message.toString());
        assertEquals(1, message.getQos());
    }

    @Test
    public void checkSubscriberQoS1ReceiveQoS2publishes_downgrade() throws Exception {
        LOG.info("*** checkSubscriberQoS1ReceiveQoS2publishes_downgrade ***");
        m_subscriber.subscribe("/topic", 1);

        m_publisher.publish("/topic", "Hello world MQTT QoS2".getBytes(UTF_8), 2, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS2", message.toString());
        assertEquals(1, message.getQos());
    }

    @Test
    public void checkSubscriberQoS2ReceiveQoS0publishes() throws Exception {
        LOG.info("*** checkSubscriberQoS2ReceiveQoS0publishes ***");
        m_subscriber.subscribe("/topic", 2);

        m_publisher.publish("/topic", "Hello world MQTT QoS2".getBytes(UTF_8), 0, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS2", message.toString());
        assertEquals(0, message.getQos());
    }

    @Test
    public void checkSubscriberQoS2ReceiveQoS1publishes() throws Exception {
        LOG.info("*** checkSubscriberQoS2ReceiveQoS1publishes ***");
        m_subscriber.subscribe("/topic", 2);

        m_publisher.publish("/topic", "Hello world MQTT QoS2".getBytes(UTF_8), 1, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS2", message.toString());
        assertEquals(1, message.getQos());
    }

    @Test
    public void checkSubscriberQoS2ReceiveQoS2publishes() throws Exception {
        LOG.info("*** checkSubscriberQoS2ReceiveQoS2publishes ***");
        m_subscriber.subscribe("/topic", 2);

        m_publisher.publish("/topic", "Hello world MQTT QoS2".getBytes(UTF_8), 2, false);
        Awaitility.await().until(m_callback::isMessageReceived);
        MqttMessage message = m_callback.retrieveMessage();
        assertEquals("Hello world MQTT QoS2", message.toString());
        assertEquals(2, message.getQos());
    }

}
