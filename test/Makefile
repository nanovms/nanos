SUBDIR=			unit runtime go

# can't do runtime until image build is common...
SUBDIR_SKIP-test=	runtime

all test:
	$(foreach d,$(filter-out $(SUBDIR_SKIP-$@),$(SUBDIR)),$(call execute_command,$(Q) $(MAKE) -C $d $@))

test: all

include ../rules.mk
