# Repo-root helper targets. The authoritative build recipes live in the per-language manifests
# and in scripts/; this Makefile is a thin, discoverable entry point.

.PHONY: help docs docs-clean

help: ## list targets
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

docs: ## regenerate the multi-language API docs (Markdown) into docs/api/ — commit the result
	./scripts/gen-docs.sh

docs-clean: ## remove the generated API docs Markdown
	rm -rf docs/api
