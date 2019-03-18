include ../config.mk
include ../common.mk

all: test-build

test-build:
	$(MAKE) -C unit
	$(MAKE) -C go
	$(MAKE) -C runtime

test:
	$(MAKE) -C unit test
	$(MAKE) -C go test
# can't do runtime until image build is common...

clean:
	$(MAKE) -C unit clean
	$(MAKE) -C go clean
	$(MAKE) -C runtime clean

include ../rules.mk
