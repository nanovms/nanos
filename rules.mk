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

ifeq ($(UNAME_s),Darwin)
CC=		cc
else
CC=		$(CROSS_COMPILE)gcc
endif

COMPILER_VERSION := $(shell $(CC) --version)

LD=		$(CC)
LN=		ln
AWK=		awk
SED=		sed
TR=		tr
SORT=		sort
STRIP=		$(CROSS_COMPILE)strip
SYNC=		sync
TAR=		tar
OBJCOPY=	$(CROSS_COMPILE)objcopy
OBJDUMP=	$(CROSS_COMPILE)objdump
RM=		rm -f
RMDIR=		rmdir
TOUCH=		touch
UMOUNT=		umount
XXD=		xxd

# gcov
GCOV=		gcov
LCOV=		lcov
GENHTML=	genhtml

CFLAGS+=	-std=gnu11 -g
CFLAGS+=	-Wall -Werror -Wno-char-subscripts -Wno-format-truncation -Wno-unknown-warning-option -Wno-stringop-overflow
CFLAGS+=	-I$(OBJDIR)

DEPFLAGS=	-MD -MP -MT $@

KERNCFLAGS=	-nostdinc \
		-fno-builtin \
		-fpie \
		-fdata-sections \
		-ffunction-sections

ifeq ($(ARCH),x86_64)
KERNCFLAGS+=	-mno-mmx -mno-sse -mno-sse2
endif

ifeq ($(ARCH),aarch64)
KERNCFLAGS+=	-march=armv8-a+nofp+nosimd -mcpu=cortex-a72 -ffixed-x18

# Workaround for GCC 12/13 bug to avoid incorrect pointer analysis https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105523
CCMAJ=$(shell $(CC) -dumpversion | awk -F. '{print $$1}')
ifeq ($(CCMAJ),$(filter $(CCMAJ),12 13))
KERNCFLAGS+=	--param=min-pagesize=0
endif

# Don't ask clang since it doesn't know --help=target
ifeq ($(findstring clang,$(COMPILER_VERSION)),clang)
OUTLINE_ATOMICS=0
else
OUTLINE_ATOMICS=	$(shell $(CC) --help=target | grep -c outline-atomics)
endif
ifneq ($(OUTLINE_ATOMICS),0)
KERNCFLAGS+=	-mno-outline-atomics
endif
endif

ifeq ($(ARCH),riscv64)
KERNCFLAGS+=	-march=rv64gc -mabi=lp64d
endif

ifeq ($(findstring clang,$(COMPILER_VERSION)),clang)
TARGET_CFLAGS=	-target $(ARCH)-elf
endif

KERNCFLAGS+=	$(TARGET_CFLAGS) -fno-omit-frame-pointer
KERNLDFLAGS=	--gc-sections -z notext -z noexecstack -z max-page-size=4096 -L $(OBJDIR) -pie --no-dynamic-linker

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
ifeq ($(DEBUG_STRIP),)
$$(PROG-$1): $$(OBJS-$1)
	@$(MKDIR) $$(dir $$@)
	$$(call cmd,ld)
ifeq ($1,kernel.elf)
	$(call cmd,mvdis)
endif
else
LDFLAGS-$1.dbg= $$(LDFLAGS-$1)
LIBS-$1.dbg= $$(LIBS-$1)
$$(PROG-$1).dbg: $$(OBJS-$1)
	@$(MKDIR) $$(dir $$@)
	$$(call cmd,ld)
$$(PROG-$1): $$(PROG-$1).dbg
	$$(call cmd,strip)
endif
endif

DEPFILES+=	$$(DEPS-$1)
GENHEADERS+=	$$(GENHEADERS-$1)
CLEANFILES+=	$$(PROG-$1) $$(OBJS-$1) $$(DEPS-$1) $$(GENHEADERS-$1)
ifneq ($(DEBUG_STRIP),)
CLEANFILES+=	$$(PROG-$1).dbg
endif
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
	$(Q) $(RM) -d $(call reverse,$(sort $(CLEANDIRS)))

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

# Stack Smashing Protection
ifeq ($(WITHOUT_SSP),)
CFLAGS+=	-fstack-protector-strong
ifneq ($(UNAME_s),Darwin)
ifeq ($(ARCH),aarch64)
# XXX SSP on arm not working yet; check flags
KERNCFLAGS+=	-fstack-protector-all
else ifeq ($(ARCH),riscv64)
KERNCFLAGS+=	-fstack-protector-all
else
KERNCFLAGS+=	-mstack-protector-guard=global \

endif
endif
endif
