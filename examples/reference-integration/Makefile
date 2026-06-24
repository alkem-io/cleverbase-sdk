# Reference integration build helpers. Builds the cleverbase-ffi library the Go signing service
# cgo-links, and exports the linker/runtime paths the Go toolchain needs.
REPO_ROOT := $(abspath ../..)
LIB_DIR := $(REPO_ROOT)/target/debug

export CGO_ENABLED := 1
export CGO_LDFLAGS := -L$(LIB_DIR)
export LD_LIBRARY_PATH := $(LIB_DIR)
export DYLD_LIBRARY_PATH := $(LIB_DIR)

.PHONY: help lib test cover e2e lint images up down

help: ## list targets
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

lib: ## build the cleverbase-ffi library the Go service links against
	cd $(REPO_ROOT) && cargo build -p cleverbase-ffi

test: lib ## unit tests for the signing service + mock upstream
	cd signing-service && go test ./internal/...
	cd mock-upstream && go test ./...

cover: lib ## signing-service unit tests with the >=95% coverage gate
	cd signing-service && go test -coverprofile=cover.out ./internal/... && \
		total="$$(go tool cover -func=cover.out | awk '/^total:/ {print $$3}' | tr -d '%')"; \
		echo "coverage: $${total}%"; \
		awk "BEGIN { exit !($${total} >= 95) }" || { echo "coverage below 95%"; exit 1; }

e2e: lib ## credential-free OpenSSL-validated end-to-end signing (B-B + B-T)
	cd signing-service && go test ./e2e/...

lint: ## golangci-lint the Go modules
	cd signing-service && golangci-lint run ./...
	cd mock-upstream && golangci-lint run ./...
	cd web && golangci-lint run ./...

up: ## build + run the credential-free stack (mock + service + web)
	docker compose -f deploy/compose.yml up --build

down: ## stop the stack
	docker compose -f deploy/compose.yml down
