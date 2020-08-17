SUBDIR=			unit runtime go e2e

# can't do runtime until image build is common...
SUBDIR_SKIP-test=	runtime

all test:
	$(foreach d,$(filter-out $(SUBDIR_SKIP-$@),$(SUBDIR)),$(call execute_command,$(Q) $(MAKE) -C $d $@ PLATFORM=$(PLATFORM)))

test: all

include ../rules.mk
