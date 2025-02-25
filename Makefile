# submodules with go.mod files
GO_SUB_MODULES = integrations/dpop_oauth2 integrations/dpop_http integrations/dpop_grpc integrations/jti_store_redis integrations/dpop_gin
GO_MODULES_PATHS = . + $(GO_SUB_MODULES)

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
	@if [ -z "$(TAG)" ]; then \
		echo "❌ ERROR: No tag supplied. Usage: make tag TAG=<version>"; \
		exit 1; \
	fi
	@echo "🔖 Tagging all Go modules with $(TAG)..."
	@git tag "$(TAG)";
	@echo "$(TAG)";
	@for dir in $(GO_SUB_MODULES); do \
		echo "$$dir/$(TAG)"; \
		git tag "$$dir/$(TAG)"; \
	done

.PHONY: push-tags
push-tags:
	@git push --tags
	@echo "🚀 Pushed all tags to remote repository!"
