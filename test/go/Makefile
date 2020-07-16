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
	$(Q) $(MKDIR) $(OBJDIR)
	$(Q) $(LN) -sf $(PLATFORMOBJDIR)/bin/kernel.img $(OBJDIR)/kernel.img
	$(Q) $(LN) -sf $(PLATFORMOBJDIR)/boot/boot.img $(OBJDIR)/boot.img
	$(GOTEST) -v

CLEANFILES+=	$(OBJDIR)/kernel.img $(OBJDIR)/boot.img

post-clean:
	$(Q) $(GOCLEAN)
	$(Q) $(RM) -rf .staging
	$(Q) $(RM) -f $(BINARY_NAME) image ../runtime/soop.data

deps:
	GO111MODULE=on $(GOGET) github.com/nanovms/ops/lepton

.PHONY: build test clean deps

include ../../rules.mk
