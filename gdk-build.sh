#!/bin/bash

set -e

# Extract from gdk-config.json
VERSION=`jq -r '.component."aws.greengrass.clientdevices.mqtt.Moquette".version' gdk-config.json`

mvn clean package -DskipTests

cp integration/target/aws.greengrass.clientdevices.mqtt.Moquette.jar \
    greengrass-build/artifacts/aws.greengrass.clientdevices.mqtt.Moquette/${VERSION}/ \
    && cp recipe.json greengrass-build/recipes/
