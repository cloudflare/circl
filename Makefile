# I'm sure there is better way. But I would need to find it first
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH)))
GOPATH_LOCAL = $(PRJ_DIR)/build
GOPATH_DIR   = $(GOPATH_LOCAL)/src/github.com/cloudflare/circl
VENDOR_DIR   = build/go_vendor
COVER_DIR    = $(GOPATH_LOCAL)/coverage
ETC_DIR      = $(PRJ_DIR)/etc
OPTS         ?=
NOASMi       ?=
GO           ?= go
BENCH_OPTS   ?= -bench=./... -run="NonExistent"
V            ?= 0

ifeq ($(NOASM),1)
	OPTS+=$(OPTS_TAGS)
endif

ifeq ($(V),1)
	OPTS += -v              # Be verbose
endif

TARGETS= \
	hash/

fmtcheck:
	$(ETC_DIR)/fmtcheck.sh

prep-%:
	mkdir -p $(GOPATH_DIR)
	cp -rf $* $(GOPATH_DIR)/$*

test: clean $(addprefix prep-,$(TARGETS))
	GOPATH=$(GOPATH_LOCAL) $(GO) vet ./...
	GOPATH=$(GOPATH_LOCAL) $(GO) test $(OPTS) ./...

cover: clean $(addprefix prep-,$(TARGETS))
	mkdir -p $(COVER_DIR)
	GOPATH=$(GOPATH_LOCAL) $(GO) test -race -coverprofile=$(COVER_DIR)/coverage.txt \
		-covermode=atomic $(OPTS) -v ./...
clean:
	rm -rf $(GOPATH_LOCAL)
	rm -rf $(VENDOR_DIR)

go_vendor: fmtcheck clean
	mkdir -p $(VENDOR_DIR)/github_com/cloudflare/circl
	rsync -a . $(VENDOR_DIR)/github_com/cloudflare/circl --exclude=$(VENDOR_DIR) --exclude=.git --exclude=.travis.yml --exclude=README.md
	find $(VENDOR_DIR) -type f -print0 -name "*.go" | xargs -0 sed -i 's/github\.com/github_com/g'
