FROM asteurer/go_spin

COPY main.go main.go
COPY go.mod go.mod
COPY go.sum go.sum
COPY spin.toml spin.toml

RUN go mod download

ARG DOCKERHUB_USER
ARG DOCKERHUB_PASSWORD
ARG IMAGE_TAG

RUN spin build
RUN spin registry login index.docker.io -u ${DOCKERHUB_USER} -p ${DOCKERHUB_PASSWORD}
RUN spin registry push index.docker.io/${DOCKERHUB_USER}/${IMAGE_TAG}