#!/bin/bash
cp recipe.yaml target/recipe/aws.greengrass.mqtt-0.0.0.yaml
cp greengrass-mqtt-broker/build/libs/aws.greengrass.mqtt.broker-0.12.1-fat-jar.jar target/artifacts/aws.greengrass.mqtt/0.0.0/aws.greengrass.mqtt.jar
greengrass-cli component update --recipeDir target/recipe --artifactDir target/artifacts --merge "aws.greengrass.mqtt=0.0.0"
