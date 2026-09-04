# Repo-root helper targets. The authoritative build recipes live in the per-language manifests
# and in scripts/; this Makefile is a thin, discoverable entry point.

.PHONY: help docs docs-clean go-test

FFI_DEBUG_DIR := $(CURDIR)/target/debug

help: ## list targets
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

docs: ## regenerate the multi-language API docs (Markdown) into docs/api/ — commit the result
	./scripts/gen-docs.sh

docs-clean: ## remove the generated API docs Markdown
	rm -rf docs/api

go-test: ## build the debug C ABI and test the Go binding against it
	cargo build --locked -p cleverbase-ffi
	cd bindings/go && \
		CGO_LDFLAGS="-L$(FFI_DEBUG_DIR)" \
		LD_LIBRARY_PATH="$(FFI_DEBUG_DIR)" \
		DYLD_LIBRARY_PATH="$(FFI_DEBUG_DIR)" \
		go test ./...
