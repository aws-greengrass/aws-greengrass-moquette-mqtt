#!/bin/bash

set -e

mkdir -p greengrass-build/artifacts/aws.greengrass.clientdevices.mqtt.Moquette/NEXT_PATCH
mkdir -p greengrass-build/recipes

mvn clean package -DskipTests

cp integration/target/aws.greengrass.clientdevices.mqtt.Moquette.jar greengrass-build/artifacts/aws.greengrass.clientdevices.mqtt.Moquette/NEXT_PATCH/ \
    && cp recipe.json greengrass-build/recipes/
