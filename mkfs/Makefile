include ../config.mk
include ../common.mk

OUT	?= $(ROOT)/output/mkfs
CFLAGS	= -fno-stack-protector
CFLAGS	+= -g
CFLAGS	+= -fdata-sections -ffunction-sections
CFLAGS	+= $(includes)

all: mkfs dump

mkfs: $(MKFS)

dump: $(DUMP)

includes := \
	-I$(SRC)/runtime \
        -I$(SRC)/tfs \
        -I$(SRC)/unix_process \
        -I$(SRC)/x86_64 \

mkfs-srcs := \
	$(ROOT)/mkfs/mkfs.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple_parser.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \

mkfs-objs = $(call srcs-to-objs,$(ROOT),$(OUT),mkfs)

dump-srcs := \
	$(ROOT)/mkfs/dump.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \

dump-objs = $(call srcs-to-objs,$(ROOT),$(OUT),dump)

$(mkfs-objs) $(dump-objs): $(CLOSURE_TMPL)

$(MKFS): $(mkfs-objs)
	$(call cmd,host-prog)

$(DUMP): $(dump-objs)
	$(call cmd,host-prog)

clean-objs = $(mkfs-objs) $(dump-objs) $(MKFS) $(DUMP) $(CLOSURE_TMPL)

clean: default-clean

.PHONY: mkfs dump

include ../rules.mk
