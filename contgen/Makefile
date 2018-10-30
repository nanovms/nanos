include ../config.mk
include ../common.mk

OUT	?= $(ROOT)/output/contgen

all: contgen

contgen-srcs := \
	$(ROOT)/contgen/contgen.c \

contgen-objs = $(call srcs-to-objs,$(ROOT),$(OUT),contgen)

# FIXME: circular depedencies.
_contgen: $(contgen-objs)
	$(call cmd,host-prog)

contgen: $(contgen-objs)
	@ mkdir -p $(dir $(CONTGEN))
	@ echo "HOSTLD	$@"
	$(Q) $(HOSTCC) $^ -g -o $(CONTGEN)

clean-objs = $(contgen-objs) $(CONTGEN)

clean: default-clean

.PHONY: all contgen clean

include ../rules.mk