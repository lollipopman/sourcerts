export GOFLAGS := -mod=vendor -tags=static

.PHONY: help
help: ## Show the help
	@awk \
		'BEGIN { \
			printf "Usage: make <TARGETS>\n\n"; \
			printf "TARGETS:\n"; \
			FS = ":.*?## " \
		}; \
		/^[ a-zA-Z_-]+:.*?## .*$$/ {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' \
  $(MAKEFILE_LIST)

.PHONY: build
build: ## build
	pkger -o cmd/sourcerts/
	go build -o . ./...
