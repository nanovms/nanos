# Go parameters
GOBUILD=	$(GO) build
GOCLEAN=	$(GO) clean
GOTEST=		$(GO) test
GOGET=		$(GO) get
BINARY_NAME=	ops

test:
	$(Q) $(MKDIR) $(OBJDIR)
	$(Q) $(LN) -sf $(PLATFORMOBJDIR)/bin/kernel.img $(OBJDIR)/kernel.img
	$(Q) $(LN) -sf $(PLATFORMOBJDIR)/boot/boot.img $(OBJDIR)/boot.img
	$(GOTEST) -v

CLEANFILES+=	$(OBJDIR)/kernel.img $(OBJDIR)/boot.img

.PHONY: test

include ../../rules.mk
