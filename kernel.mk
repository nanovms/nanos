CFLAGS+=$(KERNCFLAGS) -DKERNEL -O3
CFLAGS+=-Wno-address # lwIP build sadness
CFLAGS+=$(INCLUDES)

ifneq (,$(findstring ftrace,$(TRACE)))
CFLAGS+= -DCONFIG_FTRACE -pg
SRCS-kernel.elf+= \
	$(SRCDIR)/unix/ftrace.c \
	$(ARCHDIR)/ftrace.s
endif

ifneq (,$(findstring tracelog,$(TRACE)))
CFLAGS+= -DCONFIG_TRACELOG
SRCS-kernel.elf+= \
	$(SRCDIR)/kernel/tracelog.c
ifneq ($(TRACELOG_FILE),)
TRACELOG_MKFS_OPTS="-t (tracelog:(file:$(TRACELOG_FILE)))"
endif
endif

ifneq (,$(findstring lockstats,$(TRACE)))
CFLAGS+= -DLOCK_STATS
SRCS-kernel.elf+= \
	$(SRCDIR)/kernel/lockstats.c
endif

ifeq ($(MANAGEMENT),telnet)
CFLAGS+= -DMANAGEMENT_TELNET
SRCS-kernel.elf+= \
	$(SRCDIR)/kernel/management_telnet.c
endif

ifneq ($(NOSMP),)
CFLAGS+=	-DSPIN_LOCK_DEBUG_NOSMP
else
CFLAGS+=	-DSMP_ENABLE
endif

VDSOGEN=	$(TOOLDIR)/vdsogen
VDSO_SRCDIR=    $(SRCDIR)/kernel
VDSO_OBJDIR=    $(OBJDIR)/vdso
VDSO_SRCS=      $(VDSO_SRCDIR)/vdso.c $(VDSO_SRCDIR)/vdso-now.c
VDSO_OBJS=      $(patsubst $(VDSO_SRCDIR)/%.c,$(VDSO_OBJDIR)/%.o,$(VDSO_SRCS))
VDSO_CFLAGS=    $(TARGET_CFLAGS) -DKERNEL -DBUILD_VDSO -I$(INCLUDES) -I$(OBJDIR) -I$(OUTDIR) -I$(SRCDIR) -fPIC -c
VDSO_LDFLAGS=   -nostdlib -fPIC -shared --build-id=none --hash-style=both --eh-frame-hdr -T$(ARCHDIR)/vdso.lds
VDSO_DEPS=      $(patsubst %.o,%.d,$(VDSO_OBJS))

LDFLAGS+=	$(KERNLDFLAGS) --undefined=_start -T linker_script

STRIPFLAGS=	-g

msg_vdsogen=    VDSOGEN	$@
cmd_vdsogen=    $(VDSOGEN) $(VDSO_OBJDIR)/vdso.so $@

msg_vdso_cc=    CC	$@
cmd_vdso_cc=    $(CC) $(DEPFLAGS) $(VDSO_CFLAGS) -c $< -o $@

msg_vdso_ld=    LD	$@
cmd_vdso_ld=    $(LD) $(VDSO_LDFLAGS) $(VDSO_OBJS) -o $@

msg_objcopy=	OBJCOPY	$@
cmd_objcopy=	$(OBJCOPY) $(OBJCOPYFLAGS) $(OBJCOPYFLAGS_$(@F)) $< $@

msg_objdump=	OBJDUMP	$@
cmd_objdump=	$(OBJDUMP) $(OBJDUMPFLAGS) $(OBJDUMPFLAGS_$(@F)) $< $< >$@

msg_sed=	SED	$@
cmd_sed=	$(SED) -e 's/\#/%/' <$^ >$@

msg_version=	VERSION	$@
cmd_version=	$(MKDIR) $(dir $@); $(ECHO) "\#include <runtime.h>\nconst sstring gitversion = ss_static_init(\"$(shell $(GIT) rev-parse HEAD)\");" >$@

include ../../klib/klib.mk

include ../../rules.mk

.PHONY: mkfs vdsogen boot kernel kernel.dis target image

mkfs vdsogen:
	$(Q) $(MAKE) -C $(ROOTDIR)/tools $@

target:
ifeq ($(TARGET),)
	@echo TARGET variable not specified
	@false
endif
	$(Q) $(MAKE) -C $(ROOTDIR)/test/runtime $(TARGET)

ifneq ($(NANOS_TARGET_ROOT),)
TARGET_ROOT_OPT=	-r $(NANOS_TARGET_ROOT)
endif

$(OBJDIR)/gitversion.c: $(ROOTDIR)/.git/index $(ROOTDIR)/.git/HEAD
	$(call cmd,version)

$(VDSOGEN):
	@$(MAKE) -C $(ROOTDIR)/tools vdsogen

$(VDSO_OBJDIR)/%.o: $(VDSO_SRCDIR)/%.c
	@$(MKDIR) $(dir $@)
	$(call cmd,vdso_cc)

$(VDSO_OBJDIR)/vdso.so: $(VDSO_OBJS)
	$(call cmd,vdso_ld)

$(VDSO_OBJDIR)/vdso-image.c: $(VDSOGEN) $(VDSO_OBJDIR)/vdso.so
	$(call cmd,vdsogen)

$(PROG-kernel.elf): linker_script klib-syms $(VDSO_OBJDIR)/vdso-image.c

$(KERNEL): $(PROG-kernel.elf)
	$(call cmd,strip)

$(OBJDIR)/kernel.dis: $(KERNEL)
	$(call cmd,objdump)

msg_klib_cc=    $(msg_cc)
cmd_klib_cc=    $(CC) $(DEPFLAGS) $(KLIB_CFLAGS) -c $< -o $@

msg_klib_ld=    $(msg_ld)
cmd_klib_ld=    $(LD) $(KLIB_LDFLAGS) $^ -o $@

msg_add_syms=	KLIB_SYMS	$@
cmd_add_syms=	$(foreach prog, $(KLIB_BINARIES), $(call add_syms,$(prog)))

define build_klib

PROG-$1=	$(OBJDIR)/bin/$1
OBJS-$1=	$$(foreach s,$$(filter %.c %.s %.S,$$(SRCS-$1)),$$(call objfile,.o,$$s))
OBJDIRS-$1=	$$(sort $$(dir $$(OBJS-$1)))
DEPS-$1=	$$(patsubst %.o,%.d,$$(OBJS-$1))

$1: $$(PROG-$1)

ifneq ($$(OBJS-$1),)
$$(PROG-$1).dbg: $$(OBJS-$1)
	@$(MKDIR) $$(dir $$@)
	$$(call cmd,klib_ld)
$$(PROG-$1): $$(PROG-$1).dbg
	$$(call cmd,strip)
endif

DEPFILES+=		$$(DEPS-$1)
CLEANFILES+=	$$(PROG-$1) $$(PROG-$1).dbg $$(OBJS-$1) $$(DEPS-$1) $$(GENHEADERS-$1)
CLEANDIRS+=		$$(OBJDIRS-$1)

endef

# append list of undefined symbols to linker script
define add_syms

	$(Q) $(OBJDUMP) -R $1 | $(SED) -n -E 's/.*(GLOB_DAT|JUMP_SLOT|RISCV_64)[[:space:]]*/EXTERN(/p' | $(SED) -n 's/$$/)/p' >> $(KLIB_SYMS)

endef

$(foreach klib, $(KLIBS), $(eval $(call build_klib,$(klib))))

klib-syms: $(KLIB_SYMS)

$(KLIB_SYMS): $(KLIB_BINARIES)
	$(Q) $(RM) $(KLIB_SYMS)
	$(call cmd,add_syms)
# remove duplicated lines in linker script
	$(Q) $(SED) -i.bak -n 'G; s/\n/&&/; /^\([^\n]*\n\).*\n\1/d; s/\n//; h; P' $(KLIB_SYMS)
# delete linker script backup file
	$(Q) $(RM) $(KLIB_SYMS).bak

$(OBJDIR)/klib/%.o: $(KLIB_DIR)/%.c $(GENHEADERS)
	@$(MKDIR) $(dir $@)
	$(call cmd,klib_cc)

$(OBJDIR)/vendor/mbedtls/%.o: $(MBEDTLS_DIR)/%.c $(GENHEADERS)
	@$(MKDIR) $(dir $@)
	$(call cmd,klib_cc)
