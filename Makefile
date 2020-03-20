# I'm sure there is better way. But I would need to find it first
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH)))
GOPATH_BUILD = $(PRJ_DIR)/build
COVER_DIR    = $(GOPATH_BUILD)/coverage
TOOLS_DIR   ?= $(GOPATH)/bin
ETC_DIR      = $(PRJ_DIR)/.etc
OPTS         ?=
NOASM        ?=
GO           ?= go
GOLANGCILINT ?= $(TOOLS_DIR)/golangci-lint
# -run="^_" as we want to avoid running tests by 'bench' and there never be a test starting with _
BENCH_OPTS   ?= -bench=. -run="^_" -benchmem
V            ?= 1
GOARCH       ?=
BUILD_ARCH   = $(shell $(GO) env GOARCH)

ifeq ($(NOASM),1)
	OPTS+=--tags noasm
endif

ifeq ($(V),1)
	OPTS += -v              # Be verbose
endif

lint:
	$(GOLANGCILINT) run --config $(ETC_DIR)/golangci.yml ./...

build:
	$(GO) build ./...

test: clean
	$(GO) vet ./...
	$(GO) test $(OPTS) ./...

bench: clean
	$(GO) test $(BENCH_OPTS) $(OPTS) ./...

cover: clean
	mkdir -p $(COVER_DIR)
	$(GO) test -race -coverprofile=$(COVER_DIR)/coverage.txt -covermode=atomic $(OPTS) ./...
	$(GO) tool cover -html $(COVER_DIR)/coverage.txt -o $(COVER_DIR)/coverage.html

generate: clean
	$(GO) generate -v ./...

bootstrap:
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(TOOLS_DIR) v1.18.0

clean:
	rm -rf $(GOPATH_BUILD)
