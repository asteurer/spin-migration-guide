#!/bin/bash
set -a
source ../../.env
set +a

# docker build . \
#     --build-arg DOCKERHUB_USER=$DOCKERHUB_USER \
#     --build-arg DOCKERHUB_PASSWORD=$DOCKERHUB_PASSWORD \
#     --build-arg IMAGE_TAG=$IMAGE_TAG

# spin up --from-registry index.docker.io/asteurer/test_app
spin build --up