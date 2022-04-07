PROGRAMS=	stage2.elf

SRCS-stage2.elf= \
	$(CURDIR)/stage2.c \
	$(CURDIR)/service32.s \
	$(SRCDIR)/drivers/ata.c \
	$(SRCDIR)/kernel/elf.c \
	$(SRCDIR)/kernel/page.c \
	$(SRCDIR)/kernel/pagecache.c \
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
	$(SRCDIR)/x86_64/page.c \
	$(SRCDIR)/x86_64/serial.c \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c

CFLAGS+=	$(KERNCFLAGS) -Os -DBOOT -DPAGE_USE_FLUSH -fno-pic
CFLAGS+= \
	-I$(CURDIR) \
	-I$(SRCDIR) \
	-I$(SRCDIR)/boot \
	-I$(SRCDIR)/tfs \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/x86_64
LDFLAGS+=	$(KERNLDFLAGS) -T linker_script
AFLAGS+=	-I$(SRCDIR)/x86_64 -felf

NASMFLAGS	= -l $@.lst -I $(SRCDIR)/x86_64/ -dSTAGE2SIZE=$(shell $(SIZE_CMD) $(OBJDIR)/stage2.pad)
DDFLAGS		= bs=512 conv=sync
OBJCOPYFLAGS	= -S -O binary

msg_cat=	CAT	$@
cmd_cat=	$(CAT) $^ > $@

msg_nasm_ld=	NASM_LD	$@
cmd_nasm_ld=	$(AS) $(NASMFLAGS) $(NASMFLAGS_$(@F)) $< -o $@

msg_dd=		DD	$@
cmd_dd=		$(DD) if=$< of=$@ $(DDFLAGS) $(DDFLAGS_$(@F))

msg_objcopy=	OBJCOPY	$@
cmd_objcopy=	$(OBJCOPY) $(OBJCOPYFLAGS) $(OBJCOPYFLAGS_$(@F)) $< $@

SRCS-uefi= \
	$(SRCDIR)/boot/uefi.c \
	$(SRCDIR)/kernel/elf.c \
	$(SRCDIR)/kernel/page.c \
	$(SRCDIR)/kernel/pagecache.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/rbtree.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/sg.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c \
	$(SRCDIR)/x86_64/elf64.c \
	$(SRCDIR)/x86_64/page.c \
	$(SRCDIR)/x86_64/uefi.c \

OBJDIR-uefi= $(OBJDIR)/uefi

OBJS-uefi= $(patsubst $(SRCDIR)/%.c,$(OBJDIR-uefi)/%.o,$(SRCS-uefi)) \
	$(OBJDIR-uefi)/x86_64/uefi-crt0.o
DEPS-uefi= $(patsubst %.o,%.d,$(OBJS-uefi))
AFLAGS-uefi= -felf64
CFLAGS-uefi= \
	-Wall -Werror -fpic -fshort-wchar -mno-red-zone -mno-avx -O3 -std=gnu11 \
	-ffreestanding \
	-I$(SRCDIR) -I$(SRCDIR)/boot -I$(SRCDIR)/kernel -I$(SRCDIR)/runtime \
	-I$(SRCDIR)/tfs -I$(SRCDIR)/x86_64 -I$(OBJDIR) \
	-DBOOT -DUEFI -DEFIAPI="__attribute__((ms_abi))"
LDLAGS-uefi= -nostdlib -shared -Bsymbolic -T $(SRCDIR)/x86_64/uefi.lds

DEPFILES+= $(DEPS-uefi)

OBJDIRS-uefi= $(sort $(dir $(OBJS-uefi))) $(OBJDIR)/uefi

all: boot

include ../../../rules.mk

CLEANFILES+=	$(foreach f,boot.img stage1 stage1.lst stage2.pad stage2.bin stage2.strip uefi.so bootx64.efi,$(OBJDIR)/$f) $(OBJS-uefi) $(DEPS-uefi)
CLEANDIRS+=     $(OBJDIR)/platform/pc $(OBJDIR)/platform $(OBJDIRS-uefi)

.PHONY: boot

boot: $(OBJDIR)/boot.img $(OBJDIR)/bootx64.efi

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
CFLAGS-uefi+=	-target x86_64-elf
LD=		x86_64-elf-ld
STRIP=		x86_64-elf-strip
OBJCOPY=	/usr/local/opt/binutils/bin/objcopy
SIZE_CMD=	stat -f %z
else
LD=		$(CROSS_COMPILE)ld
CFLAGS+=	-m32
CFLAGS-uefi+=	-maccumulate-outgoing-args
SIZE_CMD=	stat -c %s
endif

msg_uefi_as=    AS	$@
cmd_uefi_as=    $(AS) $(ASDEPFLAGS) $(AFLAGS-uefi) $< -o $@

msg_uefi_cc=    CC	$@
cmd_uefi_cc=    $(CC) $(DEPFLAGS) $(CFLAGS-uefi) -c $< -o $@

msg_uefi_ld=    LD	$@
cmd_uefi_ld=    $(LD) $(LDLAGS-uefi) $(OBJS-uefi) -o $@

msg_uefi_objcopy=    OBJCOPY	$(OBJDIR)/bootx64.efi
cmd_uefi_objcopy=    $(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym  -j .rel -j .rela -j .rel.* -j .rela.* -j .rel* -j .rela* -j .reloc --target efi-app-x86_64 --subsystem=10 $< $@

$(OBJDIR-uefi)/x86_64/uefi-crt0.o:	$(SRCDIR)/x86_64/uefi-crt0.s
	$(call cmd,uefi_as)

$(OBJDIR-uefi)/%.o: $(SRCDIR)/%.c
	@$(MKDIR) $(dir $@)
	$(call cmd,uefi_cc)

$(OBJDIR)/uefi.so:	$(OBJS-uefi)
	$(call cmd,uefi_ld)

$(OBJDIR)/bootx64.efi:	$(OBJDIR)/uefi.so
	$(call cmd,uefi_objcopy)
