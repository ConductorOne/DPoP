.PHONY: all protogen

# Default target
all: protogen

protogen:
	@echo "Generating protobuf files..."
	pushd protos > /dev/null; buf generate .; popd > /dev/null
	@echo "Protobuf generation complete."