# paths
makefile_dir=	$(patsubst %/,%,$(dir $(abspath $(firstword $(filter $1, $(MAKEFILE_LIST))))))
CURDIR=		$(call makefile_dir, Makefile)
ROOTDIR=	$(call makefile_dir, %rules.mk)
SRCDIR=		$(ROOTDIR)/src
OUTDIR=		$(ROOTDIR)/output
OBJDIR=		$(subst $(ROOTDIR),$(OUTDIR),$(CURDIR))
VENDORDIR=	$(ROOTDIR)/vendor
TOOLDIR=	$(OUTDIR)/tools/bin
PATCHDIR=	$(ROOTDIR)/patches
UNAME_s=	$(shell uname -s)

# If no platform is specified, try to guess it from the host architecture.
ifeq ($(PLATFORM),)
ARCH?=		$(shell uname -m)
ifeq ($(ARCH),aarch64)
PLATFORM?=	virt
endif
ifeq ($(ARCH),x86_64)
PLATFORM?=	pc
endif
ifeq ($(ARCH),riscv64)
PLATFORM?=	riscv-virt
endif
else
# Otherwise, assume we're cross-compiling, and derive the arch from the platform.
ifeq ($(PLATFORM),virt)
ARCH?=		aarch64
endif
ifeq ($(PLATFORM),pc)
ARCH?=		x86_64
endif
ifeq ($(PLATFORM),riscv-virt)
ARCH?=		riscv64
endif
ifneq ($(ARCH),$(shell uname -m))
CROSS_COMPILE?=	$(ARCH)-linux-gnu-
endif
endif

PLATFORMDIR=	$(ROOTDIR)/platform/$(PLATFORM)
PLATFORMOBJDIR=	$(subst $(ROOTDIR),$(OUTDIR),$(PLATFORMDIR))
ARCHDIR=	$(SRCDIR)/$(ARCH)

IMAGE=		$(OUTDIR)/image/disk.raw
DEFAULT_KERNEL_TARGET= kernel

include $(SRCDIR)/drivers/acpica.mk
include $(SRCDIR)/runtime/files.mk

# To reveal verbose build messages, override Q= in command line.
Q=		@

ECHO=		echo
CAT=		cat
# XXX llvm for darwin
CP=		cp
MV=		mv -f
DD=		dd
ifeq ($(UNAME_s),Darwin)
GNUTAR=		gnutar
else
GNUTAR=		tar
endif
GIT=		git
GO=		go
MKDIR=		mkdir -p
ifeq ($(ARCH),x86_64)
AS=		nasm
ASDEPFLAGS= -MD $(patsubst %.o,%.d,$@) -MP -MT $@
else
AS=		$(CROSS_COMPILE)as
ASDEPFLAGS=
endif

ifneq ($(CROSS_COMPILE),)
CC=		$(CROSS_COMPILE)gcc
else
ifeq ($(UNAME_s),Darwin)
CC=		cc
else
CC=		gcc
endif
endif

LD=		$(CC)
LN=		ln
AWK=		awk
SED=		sed
TR=		tr
SORT=		sort
STRIP=		$(CROSS_COMPILE)strip
TAR=		tar
OBJCOPY=	$(CROSS_COMPILE)objcopy
OBJDUMP=	$(CROSS_COMPILE)objdump
RM=		rm -f
TOUCH=		touch
XXD=		xxd

# gcov
GCOV=		gcov
LCOV=		lcov
GENHTML=	genhtml

CFLAGS+=	-std=gnu11 -g
CFLAGS+=	-Wall -Werror -Wno-char-subscripts -Wno-format-truncation -Wno-unknown-warning-option
CFLAGS+=	-I$(OBJDIR)

DEPFLAGS=	-MD -MP -MT $@

KERNCFLAGS=	-nostdinc \
		-fno-builtin \
		-fdata-sections \
		-ffunction-sections

ifeq ($(ARCH),x86_64)
KERNCFLAGS+=    -mno-sse \
		-mno-sse2
endif

ifeq ($(ARCH),aarch64)
OUTLINE_ATOMICS=	$(shell $(CC) --help=target | grep -c outline-atomics)
ifneq ($(OUTLINE_ATOMICS),0)
KERNCFLAGS+=	-mno-outline-atomics
endif
endif

KERNCFLAGS+=	-fno-omit-frame-pointer
KERNLDFLAGS=	--gc-sections -z max-page-size=4096 -L $(OUTDIR)/klib

ifneq ($(UBSAN),)
KERNCFLAGS+= -fsanitize=undefined -fno-sanitize=alignment,null -fsanitize-undefined-trap-on-error
endif

ifeq ($(MEMDEBUG),mcache)
CFLAGS+= -DMEMDEBUG_MCACHE
else ifeq ($(MEMDEBUG),backed)
CFLAGS+= -DMEMDEBUG_BACKED
else ifeq ($(MEMDEBUG),all)
CFLAGS+= -DMEMDEBUG_ALL
endif

.PHONY: $(OUTDIR)/debug.h.tmp
$(OUTDIR)/debug.h.tmp:
	@$(MKDIR) $(dir $@)
ifeq ($(DEBUG),all)
	@$(CP) $(SRCDIR)/debug_all.h $@
else
ifneq ($(DEBUG),)
	@echo $(DEBUG) | $(TR) '[:lower:]' '[:upper:]' | $(SORT) | $(SED) -e 's/\s*//g' -e 's/,/\n/g' | $(SED) -e 's/^\(.*\)$$/\#define \1_DEBUG/g' > $@
else
	@$(CAT) /dev/null > $@
endif
endif

$(OUTDIR)/debug.h: $(OUTDIR)/debug.h.tmp
	@if ! (cmp -s $< $@); then $(CP) $< $@; fi

GENHEADERS+=	$(OUTDIR)/debug.h

TARGET_ROOT=	$(NANOS_TARGET_ROOT)
GCC_VER=	6
# crtbegin/crtend for dynamically linked executables
OBJS_CRTBEGIN_D=-dynamic-linker /lib64/ld-linux-x86-64.so.2 $(TARGET_ROOT)/usr/lib/x86_64-linux-gnu/Scrt1.o $(TARGET_ROOT)/usr/lib/x86_64-linux-gnu/crti.o $(TARGET_ROOT)/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VER)/crtbeginS.o
OBJS_CRTEND_D=	-L=/usr/lib/x86_64-linux-gnu -L=/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VER) -lc $(TARGET_ROOT)/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VER)/crtendS.o $(TARGET_ROOT)/usr/lib/x86_64-linux-gnu/crtn.o
# crtbegin/crtend for statically linked executables
OBJS_CRTBEGIN=	$(TARGET_ROOT)/usr/lib/x86_64-linux-gnu/crt1.o $(TARGET_ROOT)/usr/lib/x86_64-linux-gnu/crti.o $(TARGET_ROOT)/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VER)/crtbeginT.o
OBJS_CRTEND=	-L=/usr/lib/x86_64-linux-gnu -L=/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VER) --start-group -lgcc -lgcc_eh -lc --end-group $(TARGET_ROOT)/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VER)/crtend.o $(TARGET_ROOT)/usr/lib/x86_64-linux-gnu/crtn.o

##############################################################################
# functions

# reverse list
reverse=	$(if $(1),$(call reverse,$(wordlist 2,$(words $(1)),$(1)))) $(firstword $(1))

# execute command (additional empty line is necessary!)
define execute_command
$1

endef

# get object file from source file
# $1 - object file suffix (.o)
# $2 - source file
objfile=	$(patsubst $(ROOTDIR)/%$(suffix $2),$(OBJDIR)/%$1,$2)

cc-option=	$(shell if $(CC) -Werror $(1) -S -o /dev/null -xc /dev/null \
	> /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

cmd=		$(if $(Q),@ echo "$(msg_$(1))";) $(cmd_$(1))

##############################################################################
# commands

msg_ld=		LD	$@
cmd_ld=		$(LD) $(LDFLAGS) $(LDFLAGS-$(@F)) $(OBJS_BEGIN) $(filter %.o,$^) $(LIBS-$(@F)) $(OBJS_END) -o $@

msg_cc=		CC	$@
cmd_cc=		$(CC) $(DEPFLAGS) $(CFLAGS) $(CFLAGS-$(<F)) -c $< -o $@

msg_as=		AS	$@
cmd_as=		$(AS) $(ASDEPFLAGS) $(AFLAGS) $(AFLAGS-$(<F)) $< -o $@

msg_go=		GO	$@
cmd_go=		$(GO_ENV) $(GO) build $(GOFLAGS) -o $@ $^

msg_strip=	STRIP	$@
cmd_strip=	$(STRIP) $(STRIPFLAGS) $(STRIPFLAGS-$(<F)) $< -o $@

msg_mvdis=	MV	kernel.dis kernel.dis.old
cmd_mvdis=  if [ -f $(OBJDIR)/kernel.dis ]; then $(MV) $(OBJDIR)/kernel.dis $(OBJDIR)/kernel.dis.old; fi

msg_contgen=	CONTGEN	$@
cmd_contgen=	$(CONTGEN) 10 10 >$@

msg_vendor=	VENDOR	$@
cmd_vendor=	$(RM) -r $(@D) && $(GIT) clone $(GITFLAGS) $(@D) && $(TOUCH) $@ && \
	([ ! -f $(PATCHDIR)/$(notdir $(@D)).patch ] || (patch -p1 -d$(@D) < $(PATCHDIR)/$(notdir $(@D)).patch))

##############################################################################
# build a program

define build_program
PROG-$1=	$(OBJDIR)/bin/$1
OBJS-$1=	$$(foreach s,$$(filter %.c %.s %.S,$$(SRCS-$1)),$$(call objfile,.o,$$s))
OBJDIRS-$1=	$$(sort $$(dir $$(OBJS-$1)))
GENHEADERS-$1=	$(OBJDIR)/closure_templates.h
DEPS-$1=	$$(patsubst %.o,%.d,$$(OBJS-$1))

.PHONY: $1

$1: $$(PROG-$1)

ifneq ($$(OBJS-$1),)
$$(PROG-$1): $$(OBJS-$1)
	@$(MKDIR) $$(dir $$@)
	$$(call cmd,ld)
ifeq ($1,kernel.elf)
	$(call cmd,mvdis)
endif
endif

DEPFILES+=	$$(DEPS-$1)
GENHEADERS+=	$$(GENHEADERS-$1)
CLEANFILES+=	$$(PROG-$1) $$(OBJS-$1) $$(DEPS-$1) $$(GENHEADERS-$1)
CLEANDIRS+=	$(OBJDIR)/bin $(OBJDIR)/src $$(OBJDIRS-$1)
endef

$(foreach prog, $(PROGRAMS) $(ADDITIONAL_PROGRAMS), $(eval $(call build_program,$(prog))))

ifeq ($(filter print-% clean cleandepend,$(MAKECMDGOALS)),)
-include $(sort $(DEPFILES))
endif

PROGRAM_BINARIES= $(foreach prog, $(PROGRAMS), $(OBJDIR)/bin/$(prog))

##############################################################################
# closure_templates

ifeq ($(CONTGEN),)
CONTGEN=	$(OUTDIR)/tools/bin/contgen
$(CONTGEN):
	@$(MAKE) -C $(ROOTDIR)/tools contgen
endif

$(OBJDIR)/closure_templates.h: $(CONTGEN)
	@$(MKDIR) $(dir $@)
	$(call cmd,contgen)

##############################################################################
# clean

.PHONY: clean pre-clean do-clean post-clean
.PHONY: cleandepend

pre-clean:

do-clean: pre-clean
	$(foreach d,$(SUBDIR),$(call execute_command,$(Q) $(MAKE) -C $d clean))
	$(Q) $(RM) $(CLEANFILES)
	$(Q) $(RM) -d $(call reverse,$(sort $(CLEANDIRS))) $(OBJDIR)

post-clean: do-clean

clean: post-clean

cleandepend:
	$(foreach d,$(SUBDIR),$(call execute_command,$(Q) $(MAKE) -C $d cleandepend))
	$(Q) $(RM) $(DEPFILES)

##############################################################################
# implicit rules

.SUFFIXES:

$(OBJDIR)/%.o: $(ROOTDIR)/%.s $(OBJDIR)/%.d
	@$(MKDIR) $(dir $@)
	$(call cmd,as)

# run .S files through gcc for preprocessing
$(OBJDIR)/%.o: $(ROOTDIR)/%.S $(OBJDIR)/%.d | $(sort $(GENHEADERS))
	@$(MKDIR) $(dir $@)
	$(call cmd,cc)

$(OBJDIR)/%.o: $(ROOTDIR)/%.c $(OBJDIR)/%.d | $(sort $(GENHEADERS))
	@$(MKDIR) $(dir $@)
	$(call cmd,cc)

$(DEPFILES):

$(OBJDIR)/bin/%: %.go
	@$(MKDIR) $(dir $@)
	$(call cmd,go)

%/.vendored:
	$(call cmd,vendor)

##############################################################################
# other rules

.PHONY: all

print-%:
	@echo "$* = [$($*)]"

ifneq ($(CURDIR),$(ROOTDIR))
-include $(ROOTDIR)/Makefile.local
endif
-include Makefile.local

ifdef BUILD_KERNEL_DIS
DEFAULT_KERNEL_TARGET=	kernel.dis
BUILD_KERNEL_DIS= $(OBJDIR)/kernel.dis
endif

CLEANFILES+= $(OBJDIR)/kernel.dis.old $(OUTDIR)/debug.h $(OUTDIR)/debug.h.tmp

# Stack Smashing Protection
ifeq ($(WITHOUT_SSP),)
CFLAGS+=	-fstack-protector-strong
ifneq ($(CC),clang)
ifneq ($(UNAME_s),Darwin)
ifeq ($(ARCH),aarch64)
# XXX SSP on arm not working yet; check flags
KERNCFLAGS+=	-fstack-protector-all
else ifeq ($(ARCH),riscv64)
KERNCFLAGS+=	-fstack-protector-all
else
KERNCFLAGS+=	-mstack-protector-guard=global \
		-fno-pic
endif
endif
endif
endif
