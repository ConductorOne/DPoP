# Entry point for the Go program
ENTRYPOINT=entrypoint/main.go

# Default GOOS and GOARCH
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# Output directory
BUILD_DIR=build/$(GOARCH)_$(GOOS)
BINARY_NAME=$(BUILD_DIR)/c1-lambda

# Docker image settings
DOCKER_IMAGE_NAME=c1-lambda
DOCKER_PLATFORM=linux/arm64

.PHONY: all build clean run docker-build

# Default target
all: build

# Build the Go binary
build:
	mkdir -p $(BUILD_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BINARY_NAME) $(ENTRYPOINT)

# Clean the build directory
clean:
	rm -rf build

# Run the binary
run: build
	./$(BINARY_NAME)

protogen:
	@echo "Generating protobuf files..."
	pushd protos > /dev/null; buf generate .; popd > /dev/null
	@echo "Protobuf generation complete."

# Build a Docker container for linux/amd64
docker-build:
	docker buildx build --platform $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE_NAME) .