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
	go build -o . ./...

uname=$(shell uname -r)

build-elf: ## build eBPF elf object
	clang-12 \
		-D__KERNEL__ \
		-O2 -emit-llvm -c sourcerts.c \
		-Wno-address-of-packed-member \
		-Wno-pointer-sign \
		-I ./include \
		-I /lib/modules/$(uname)/source/include \
		-I /usr/include/bpf/include \
		-I /lib/modules/$(uname)/source/arch/x86/include \
		-I /lib/modules/$(uname)/build/include \
		-I /lib/modules/$(uname)/build/arch/x86/include/generated \
		-o - | \
		llc-12 -march=bpf -filetype=obj -o sourcerts.o
