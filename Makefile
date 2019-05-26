# I'm sure there is better way. But I would need to find it first
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH)))
GOPATH_LOCAL = $(PRJ_DIR)/build
VENDOR_DIR   = $(GOPATH_LOCAL)/vendor
COVER_DIR    = $(GOPATH_LOCAL)/coverage
ETC_DIR      = $(PRJ_DIR)/etc
OPTS         ?= -v
NOASM        ?=
GO           ?= go
# -run="^_" as we want to avoid running tests by 'bench' and there never be a test starting with _
BENCH_OPTS   ?= -v -bench=. -run="^_" -benchmem
V            ?= 0
GOARCH       ?=
BUILD_ARCH   = $(shell $(GO) env GOARCH)

ifeq ($(NOASM),1)
	OPTS+=$(OPTS_TAGS)
endif

ifeq ($(V),1)
	OPTS += -v              # Be verbose
endif

fmtcheck:
	$(ETC_DIR)/fmtcheck.sh

test: clean
	$(GO) vet ./...
	$(GO) test $(OPTS) ./...

bench: clean 
	$(GO) test $(BENCH_OPTS) ./...

cover: clean
	mkdir -p $(COVER_DIR)
	$(GO) test -race -coverprofile=$(COVER_DIR)/coverage.txt \
		-covermode=atomic $(OPTS) ./...

generate: clean
	$(GO) generate -v ./...

clean:
	rm -rf $(GOPATH_LOCAL)
	rm -rf $(VENDOR_DIR)

vendor: fmtcheck clean
	mkdir -p $(VENDOR_DIR)/github_com/cloudflare/circl
	rsync -a . $(VENDOR_DIR)/github_com/cloudflare/circl \
		--exclude=$(VENDOR_DIR) \
		--exclude=.git          \
		--exclude=.travis.yml   \
		--exclude=README.md     \
		--exclude=Makefile      \
		--exclude=build
	# This swaps all imports with github.com to github_com, so that standard library doesn't
	# try to access external libraries.
	find $(VENDOR_DIR) -type f -iname "*.go" -print0  | xargs -0 sed -i 's/github\.com/github_com/g'
