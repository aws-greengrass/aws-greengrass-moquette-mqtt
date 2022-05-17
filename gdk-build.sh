#!/bin/bash

cp target/aws.greengrass.clientdevices.mqtt.Moquette.jar greengrass-build/artifacts/aws.greengrass.clientdevices.mqtt.Moquette/NEXT_PATCH/ \
	&& cp recipe.json greengrass-build/recipes/
