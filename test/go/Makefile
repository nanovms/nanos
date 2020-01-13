# Go parameters
GOBUILD=	$(GO) build
GOCLEAN=	$(GO) clean
GOTEST=		$(GO) test
GOGET=		$(GO) get
BINARY_NAME=	ops

all: build

build: deps
	$(GOBUILD)

test: build
	$(GOTEST) -v

post-clean:
	$(Q) $(GOCLEAN)
	$(Q) $(RM) -rf .staging
	$(Q) $(RM) -f $(BINARY_NAME) image ../runtime/soop.data

deps:
	GO111MODULE=on $(GOGET) github.com/nanovms/ops/lepton

.PHONY: build test clean deps

include ../../rules.mk
