FROM asteurer/javascript_spin

COPY /src /src
COPY package.json package.json
COPY spin.toml spin.toml
COPY webpack.config.js webpack.config.js
COPY tsconfig.json tsconfig.json

ARG DOCKERHUB_USER
ARG DOCKERHUB_PASSWORD
ARG IMAGE_TAG

RUN npm install

RUN spin build
RUN spin registry login index.docker.io -u ${DOCKERHUB_USER} -p ${DOCKERHUB_PASSWORD}
RUN spin registry push index.docker.io/${DOCKERHUB_USER}/${IMAGE_TAG}