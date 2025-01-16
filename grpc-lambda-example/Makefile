# Docker image settings
DOCKER_IMAGE_NAME=grpc-lambda-example
DOCKER_PLATFORM=linux/arm64

.PHONY: all sam-build sam-run docker-build tidy

all: sam-run

sam-build:
	DOCKER_HOST=unix://$(HOME)/.docker/run/docker.sock sam build

sam-run: sam-build
	DOCKER_HOST=unix://$(HOME)/.docker/run/docker.sock sam local start-lambda

docker-build:
	pushd grpc-lambda-example && docker buildx build --platform $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE_NAME) . && popd

tidy:
	pushd grpc-lambda-example && go mod tidy && go mod vendor &&  popd
