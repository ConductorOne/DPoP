# submodules with go.mod files
GO_MODULES_PATHS = . integrations/dpop_oauth2 integrations/dpop_http integrations/dpop_grpc integrations/jti_store_redis integrations/dpop_gin

update-deps:
	for path in $(GO_MODULES_PATHS); do \
		pushd $$path > /dev/null && go get -u ./... && go mod tidy && popd > /dev/null; \
	done

test:
	for path in $(GO_MODULES_PATHS); do \
		pushd $$path > /dev/null && go test -v ./... && popd > /dev/null; \
	done

.PHONY: tag
tag:
	@if [ -z "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
		echo "❌ ERROR: No tag supplied. Usage: make tag <version>"; \
		exit 1; \
	fi
	@echo "Tagging all Go modules with $(filter-out $@,$(MAKECMDGOALS))..."
	@go run tag.go $(filter-out $@,$(MAKECMDGOALS))
