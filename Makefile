# I'm sure there is better way. But I would need to find it first
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH)))
GOPATH_LOCAL = $(PRJ_DIR)/build
GOPATH_DIR   = $(GOPATH_LOCAL)/src/github.com/cloudflare/circl
VENDOR_DIR   = build/vendor
COVER_DIR    = $(GOPATH_LOCAL)/coverage
ETC_DIR      = $(PRJ_DIR)/etc
OPTS         ?= -v
NOASM        ?=
GO           ?= go
# -run="^_" as we want to avoid running tests by 'bench' and there never be a test starting with _
BENCH_OPTS   ?= -v -bench=. -run="^_"
V            ?= 0
GOARCH       ?=
BUILD_ARCH   = $(shell $(GO) env GOARCH)

ifeq ($(NOASM),1)
	OPTS+=$(OPTS_TAGS)
endif

ifeq ($(V),1)
	OPTS += -v              # Be verbose
endif

TARGETS= \
	hash/	\
	dh/	\
	ecc/	\
	etc/ 	\
	kem/	\
	utils

# Packages with implementation only for AMD64
ifeq ($(BUILD_ARCH), amd64)
	TARGETS += ecdh
endif

fmtcheck:
	$(ETC_DIR)/fmtcheck.sh

prep-%:
	mkdir -p $(GOPATH_DIR)
	cp -rf $* $(GOPATH_DIR)/$*

test: clean $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); GOPATH=$(GOPATH_LOCAL) $(GO) vet ./...
	cd $(GOPATH_LOCAL); GOARCH=$(GOARCH) GOPATH=$(GOPATH_LOCAL) \
		$(GO) test $(OPTS) ./...

bench: clean $(addprefix prep-,$(TARGETS))
	cd $(GOPATH_LOCAL); GOPATH=$(GOPATH_LOCAL) $(GO) test \
		$(BENCH_OPTS) ./...

cover: clean $(addprefix prep-,$(TARGETS))
	mkdir -p $(COVER_DIR)
	cd $(GOPATH_LOCAL); GOPATH=$(GOPATH_LOCAL) $(GO) test \
		-race -coverprofile=$(COVER_DIR)/coverage.txt \
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
