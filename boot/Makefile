PROGRAMS=	stage2.elf

SRCS-stage2.elf= \
	$(CURDIR)/stage2.c \
	$(CURDIR)/service32.s \
	$(SRCDIR)/drivers/ata.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/rbtree.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/sg.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/x86_64/elf.c \
	$(SRCDIR)/x86_64/kvm_platform.c \
	$(SRCDIR)/x86_64/page.c \
	$(SRCDIR)/x86_64/pagecache.c \
	$(SRCDIR)/x86_64/serial.c \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c

CFLAGS+=	$(KERNCFLAGS) -DBOOT -DPAGE_USE_FLUSH
CFLAGS+= \
	-I$(CURDIR) \
	-I$(SRCDIR) \
	-I$(SRCDIR)/tfs \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/x86_64
LDFLAGS+=	$(KERNLDFLAGS) -T linker_script
AFLAGS+=	-I$(SRCDIR)/x86_64 -felf

NASMFLAGS	= -l $@.lst -dSTAGE2SIZE=$(shell $(SIZE_CMD) $(OBJDIR)/stage2.pad)
DDFLAGS		= bs=512 conv=sync
OBJCOPYFLAGS	= -S -O binary

msg_cat=	CAT	$@
cmd_cat=	$(CAT) $^ > $@

msg_nasm_ld=	NASM_LD	$@
cmd_nasm_ld=	$(NASM) $(NASMFLAGS) $(NASMFLAGS_$(@F)) $< -o $@

msg_dd=		DD	$@
cmd_dd=		$(DD) if=$< of=$@ $(DDFLAGS) $(DDFLAGS_$(@F))

msg_objcopy=	OBJCOPY	$@
cmd_objcopy=	$(OBJCOPY) $(OBJCOPYFLAGS) $(OBJCOPYFLAGS_$(@F)) $< $@

all: boot

include ../rules.mk

CLEANFILES+=	$(foreach f,boot.img stage1 stage1.lst stage2.pad stage2.bin stage2.strip,$(OBJDIR)/$f)

.PHONY: boot

boot: $(OBJDIR)/boot.img

$(OBJDIR)/boot.img: $(OBJDIR)/stage1 $(OBJDIR)/stage2.pad
	$(call cmd,cat)

$(OBJDIR)/stage1: stage1.s $(OBJDIR)/stage2.pad
	$(call cmd,nasm_ld)

$(OBJDIR)/stage2.pad: $(OBJDIR)/stage2.bin
	$(call cmd,dd)

$(OBJDIR)/stage2.bin: $(OBJDIR)/stage2.strip
	$(call cmd,objcopy)

$(OBJDIR)/stage2.strip: $(OBJDIR)/bin/stage2.elf
	$(call cmd,strip)

$(PROG-stage2.elf): linker_script

ifeq ($(UNAME_s),Darwin)
CFLAGS+=	-target i386-elf
LD=		x86_64-elf-ld
STRIP=		x86_64-elf-strip
OBJCOPY=	x86_64-elf-objcopy
SIZE_CMD=	stat -f %z
else
LD=		ld
CFLAGS+=	-m32
SIZE_CMD=	stat -c %s
endif
