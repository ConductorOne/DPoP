# submodules with go.mod files
GO_SUB_MODULES = integrations/dpop_oauth2 integrations/dpop_http integrations/dpop_grpc integrations/jti_store_redis integrations/dpop_gin
GO_MODULES_PATHS = . $(GO_SUB_MODULES)

update-deps:
	for path in $(GO_MODULES_PATHS); do \
		pushd $$path > /dev/null && go get -u ./... && go mod tidy && popd > /dev/null; \
	done

.PHONY: test
test:
	@echo "🧪 Running tests for all modules..."
	@success_count=0; \
	failure_count=0; \
	for path in $(GO_MODULES_PATHS); do \
		echo "\n📦 Testing module: $$path"; \
		if pushd $$path > /dev/null && go test -v ./...; then \
			echo "✅ Tests passed for $$path"; \
			success_count=$$((success_count + 1)); \
		else \
			echo "❌ Tests failed for $$path"; \
			failure_count=$$((failure_count + 1)); \
		fi; \
		popd > /dev/null; \
	done; \
	echo "\n📊 Test Summary: $$success_count modules succeeded, $$failure_count modules failed"; \
	if [ $$failure_count -gt 0 ]; then \
		echo "❌ Some tests failed"; \
		exit 1; \
	else \
		echo "✅ All tests passed successfully!"; \
	fi

.PHONY: bench
bench:
	@echo "🔍 Running benchmark tests for all modules..."
	@success_count=0; \
	failure_count=0; \
	for path in $(GO_MODULES_PATHS); do \
		echo "\n📊 Benchmarking module: $$path"; \
		if pushd $$path > /dev/null && go test -bench=. -benchmem ./...; then \
			echo "✅ Benchmarks completed for $$path"; \
			success_count=$$((success_count + 1)); \
		else \
			echo "❌ Benchmarks failed for $$path"; \
			failure_count=$$((failure_count + 1)); \
		fi; \
		popd > /dev/null; \
	done; \
	echo "\n📈 Benchmark Summary: $$success_count modules succeeded, $$failure_count modules failed"; \
	if [ $$failure_count -gt 0 ]; then \
		echo "❌ Some benchmarks failed"; \
		exit 1; \
	else \
		echo "✅ All benchmarks completed successfully!"; \
	fi

.PHONY: coverage
coverage:
	@echo "🔎 Running test coverage for main module only..."
	@rm -f coverage.out
	@echo "mode: atomic" > coverage.out
	@echo "\n📊 Generating coverage for main module"
	@pushd . > /dev/null; \
	if go test -mod=mod -coverprofile=profile.out -covermode=atomic ./...; then \
		if [ -f profile.out ]; then \
			tail -n +2 profile.out >> $(CURDIR)/coverage.out; \
			rm profile.out; \
		fi; \
		echo "✅ Coverage generated for main module"; \
	else \
		echo "❌ Coverage failed for main module"; \
		exit 1; \
	fi; \
	popd > /dev/null; \
	if [ -f coverage.out ]; then \
		go tool cover -func=coverage.out; \
		echo "\n📈 Coverage summary generated"; \
		echo "✅ Coverage analysis completed!"; \
	else \
		echo "❌ No coverage data generated"; \
		exit 1; \
	fi

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

.PHONY: coverage-integration
coverage-integration:
	@if [ -z "$(MODULE)" ]; then \
		echo "❌ ERROR: No module specified. Usage: make coverage-integration MODULE=integrations/dpop_gin"; \
		exit 1; \
	fi
	@echo "🔎 Running test coverage for $(MODULE)..."
	@rm -f $(MODULE)/coverage.out
	@pushd $(MODULE) > /dev/null; \
	if go test -mod=mod -coverprofile=coverage.out -covermode=atomic ./...; then \
		echo "✅ Coverage generated for $(MODULE)"; \
		go tool cover -func=coverage.out; \
		echo "\n📈 Coverage summary generated for $(MODULE)"; \
		echo "✅ Coverage analysis completed!"; \
	else \
		echo "❌ Coverage failed for $(MODULE)"; \
		exit 1; \
	fi; \
	popd > /dev/null

.PHONY: coverage-all-integrations
coverage-all-integrations:
	@echo "🔎 Running test coverage for all integration modules..."
	@for path in $(GO_SUB_MODULES); do \
		echo "\n📊 Generating coverage for module: $$path"; \
		make coverage-integration MODULE=$$path || true; \
	done
	@echo "\n✅ Coverage analysis completed for all integration modules!"
