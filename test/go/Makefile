include ../../config.mk
include ../../common.mk

# Go parameters
GOCMD?=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=ops

all: build

build:
	$(GOBUILD)

test:
	$(GOTEST) -v

clean:
	$(GOCLEAN)
	$(Q) $(RM) -rf .staging
	$(Q) $(RM) -f $(BINARY_NAME) image ../runtime/soop.data

deps:
	$(GOGET) github.com/spf13/cobra
	$(GOGET) github.com/vishvananda/netlink
	$(GOGET) github.com/jstemmer/go-junit-report
	$(GOGET) github.com/d2g/dhcp4
	$(GOGET) github.com/d2g/dhcp4client
	$(GOGET) github.com/go-errors/errors
	$(GOGET) github.com/cheggaaa/pb

