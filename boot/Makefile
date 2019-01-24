include ../config.mk
include ../common.mk

OUT		?= $(ROOT)/output/boot

ifeq ($(UNAME_s),Darwin)
CFLAGS          += -target i386-elf
LD              = x86_64-elf-ld
STRIP           = x86_64-elf-strip
OBJCOPY         = x86_64-elf-objcopy
SIZE_CMD        = stat -f %z
else
CFLAGS          += -m32
SIZE_CMD        = stat -c %s
endif
CFLAGS		+= -DBOOT -nostdinc -fno-builtin -DPAGE_USE_FLUSH
LDFLAGS		+= -T linker_script
AFLAGS		+= -felf
NASMFLAGS	= -l $@.lst -dSTAGE1SIZE=512 -dSTAGE2SIZE=$(shell $(SIZE_CMD) $(OUT)/stage2.pad)
OBJCOPYFLAGS	= -S -O binary
DDFLAGS		= bs=512 conv=sync

all: boot

boot: $(BOOTIMG)

includes = \
	-I$(ROOT)/boot \
	-I$(SRC)/tfs \
	-I$(SRC)/runtime \
	-I$(SRC)/x86_64 \

boot-srcs = \
	$(ROOT)/boot/stage2.c \
	$(ROOT)/boot/service32.s \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/string.c \
	$(SRC)/x86_64/elf.c \
	$(SRC)/x86_64/kvm_platform.c \
	$(SRC)/x86_64/page.c \
	$(SRC)/x86_64/serial.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \

boot-objs = $(call srcs-to-objs,$(ROOT),$(OUT),boot)

$(boot-objs): $(boot-srcs) $(CLOSURE_TMPL)

$(BOOTIMG): $(OUT)/stage1 $(OUT)/stage2.pad
	$(call cmd,cat)

%/stage1: stage1.s %/stage2.pad
	$(call cmd,nasm_ld)

%.pad: %.bin
	$(call cmd,dd)

%.bin: %.strip
	$(call cmd,objcopy)

%.strip: %.elf
	$(call cmd,strip)

$(OUT)/stage2.elf: $(boot-objs) linker_script
	$(call cmd,ld)

intermediate := $(addprefix $(OUT)/,stage1 stage1.lst stage2.pad stage2.bin stage2.strip stage2.elf)

.PRECIOUS: $(intermediate)

clean-objs = $(boot-objs) $(BOOTIMG) $(intermediate) $(CLOSURE_TMPL)

clean: default-clean

.PHONY: all boot clean

include ../rules.mk
