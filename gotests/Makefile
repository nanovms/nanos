
# Go parameters
GOCMD?=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test 
GOGET=$(GOCMD) get
BINARY_NAME=nvm

all: test

test: 
	$(GOTEST) -v
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

deps:
	$(GOGET) github.com/spf13/cobra
	$(GOGET) github.com/vishvananda/netlink
	$(GOGET) github.com/jstemmer/go-junit-report
	$(GOGET) github.com/d2g/dhcp4
	$(GOGET) github.com/d2g/dhcp4client
	$(GOGET) github.com/go-errors/errors  

