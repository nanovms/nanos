LWIPDIR=	$(VENDORDIR)/lwip
PROGRAMS=	stage3.img
SRCS-stage3.img= \
	$(CURDIR)/stage3.c \
	$(OBJDIR)/gitversion.c \
	$(SRCDIR)/drivers/ata.c \
	$(SRCDIR)/drivers/ata-pci.c \
	$(SRCDIR)/drivers/console.c \
	$(SRCDIR)/drivers/storage.c \
	$(SRCDIR)/drivers/vga.c \
	$(SRCDIR)/gdb/gdbstub.c \
	$(SRCDIR)/gdb/gdbtcp.c \
	$(SRCDIR)/gdb/gdbutil.c \
	$(SRCDIR)/http/http.c \
	$(SRCDIR)/net/direct.c \
	$(SRCDIR)/net/net.c \
	$(SRCDIR)/net/netsyscall.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/mcache.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/queue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/rbtree.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/sg.c \
	$(SRCDIR)/runtime/sha256.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/crypto/chacha.c \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c \
	$(SRCDIR)/unix/aio.c \
	$(SRCDIR)/unix/blockq.c \
	$(SRCDIR)/unix/exec.c \
	$(SRCDIR)/unix/eventfd.c \
	$(SRCDIR)/unix/filesystem.c \
	$(SRCDIR)/unix/futex.c \
	$(SRCDIR)/unix/mktime.c \
	$(SRCDIR)/unix/mmap.c \
	$(SRCDIR)/unix/notify.c \
	$(SRCDIR)/unix/poll.c \
	$(SRCDIR)/unix/signal.c \
	$(SRCDIR)/unix/socket.c \
	$(SRCDIR)/unix/special.c \
	$(SRCDIR)/unix/syscall.c \
	$(SRCDIR)/unix/thread.c \
	$(SRCDIR)/unix/timer.c \
	$(SRCDIR)/unix/unix_clock.c \
	$(SRCDIR)/unix/unix.c \
	$(SRCDIR)/unix/vdso.c \
	$(SRCDIR)/unix/pipe.c \
	$(SRCDIR)/virtio/virtio_net.c \
	$(SRCDIR)/virtio/virtio_pci.c \
	$(SRCDIR)/virtio/virtio_storage.c \
	$(SRCDIR)/virtio/virtio_scsi.c \
	$(SRCDIR)/virtio/virtqueue.c \
	$(SRCDIR)/virtio/scsi.c \
	$(SRCDIR)/vmware/vmxnet3_net.c \
	$(SRCDIR)/vmware/vmxnet3_queue.c \
	$(SRCDIR)/xen/xen.c \
	$(SRCDIR)/xen/xennet.c \
	$(SRCDIR)/x86_64/ap.s \
	$(SRCDIR)/x86_64/apic.c \
	$(SRCDIR)/x86_64/backed_heap.c \
	$(SRCDIR)/x86_64/breakpoint.c \
	$(SRCDIR)/x86_64/clock.c \
	$(SRCDIR)/x86_64/crt0.s \
	$(SRCDIR)/x86_64/elf.c \
	$(SRCDIR)/x86_64/flush.c \
	$(SRCDIR)/x86_64/hpet.c \
	$(SRCDIR)/x86_64/interrupt.c \
	$(SRCDIR)/x86_64/kvm_platform.c \
	$(SRCDIR)/x86_64/mp.c \
	$(SRCDIR)/x86_64/page.c \
	$(SRCDIR)/x86_64/pagecache.c \
	$(SRCDIR)/x86_64/pci.c \
	$(SRCDIR)/x86_64/pvclock.c \
	$(SRCDIR)/x86_64/rtc.c \
	$(SRCDIR)/x86_64/schedule.c \
	$(SRCDIR)/x86_64/serial.c \
	$(SRCDIR)/x86_64/service.c \
	$(SRCDIR)/x86_64/symtab.c \
	$(SRCDIR)/x86_64/synth.c \
	$(SRCDIR)/x86_64/vdso-now.c \
	$(SRCDIR)/x86_64/x2apic.c \
	$(SRCDIR)/x86_64/xapic.c \
	$(VDSO_OBJDIR)/vdso-image.c \
	$(SRCS-lwip)
SRCS-lwip= \
	$(LWIPDIR)/src/core/def.c \
	$(LWIPDIR)/src/core/inet_chksum.c \
	$(LWIPDIR)/src/core/init.c \
	$(LWIPDIR)/src/core/ip.c \
	$(LWIPDIR)/src/core/ipv4/dhcp.c \
	$(LWIPDIR)/src/core/ipv4/etharp.c \
	$(LWIPDIR)/src/core/ipv4/icmp.c \
	$(LWIPDIR)/src/core/ipv4/ip4_addr.c \
	$(LWIPDIR)/src/core/ipv4/ip4_frag.c \
	$(LWIPDIR)/src/core/ipv4/ip4.c \
	$(LWIPDIR)/src/core/ipv6/icmp6.c \
	$(LWIPDIR)/src/core/ipv6/ip6.c \
	$(LWIPDIR)/src/core/ipv6/ip6_addr.c \
	$(LWIPDIR)/src/core/ipv6/ip6_frag.c \
	$(LWIPDIR)/src/core/ipv6/mld6.c \
	$(LWIPDIR)/src/core/ipv6/nd6.c \
	$(LWIPDIR)/src/core/mem.c \
	$(LWIPDIR)/src/core/memp.c \
	$(LWIPDIR)/src/core/netif.c \
	$(LWIPDIR)/src/core/pbuf.c \
	$(LWIPDIR)/src/core/stats.c \
	$(LWIPDIR)/src/core/tcp_in.c \
	$(LWIPDIR)/src/core/tcp_out.c \
	$(LWIPDIR)/src/core/tcp.c \
	$(LWIPDIR)/src/core/timeouts.c \
	$(LWIPDIR)/src/core/udp.c \
	$(LWIPDIR)/src/api/err.c \
	$(LWIPDIR)/src/netif/ethernet.c

INCLUDES=\
	-I$(SRCDIR) \
	-I$(SRCDIR)/gdb \
	-I$(SRCDIR)/http \
	-I$(SRCDIR)/net \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/tfs \
	-I$(SRCDIR)/unix \
	-I$(SRCDIR)/unix_process \
	-I$(SRCDIR)/x86_64 \
	-I$(SRCDIR)/xen/public \
	-I$(LWIPDIR)/src/include

AFLAGS+=-I$(SRCDIR)/x86_64

CFLAGS+=$(KERNCFLAGS) -DSTAGE3 -mcmodel=kernel
CFLAGS+=$(INCLUDES)

# Enable tracing by specifying TRACE=ftrace on command line
ifeq ($(TRACE),ftrace)
CFLAGS+= -DCONFIG_FTRACE -pg
SRCS-stage3.img+= \
	$(SRCDIR)/unix/ftrace.c \
	$(SRCDIR)/x86_64/ftrace.s
endif

#CFLAGS+=	-DLWIPDIR_DEBUG -DEPOLL_DEBUG -DNETSYSCALL_DEBUG -DKERNEL_DEBUG
AFLAGS+=	-felf64 -I$(OBJDIR)/
LDFLAGS+=	$(KERNLDFLAGS) -T linker_script

VDSO_SRCDIR=    $(SRCDIR)/x86_64
VDSO_OBJDIR=    $(OBJDIR)/vdso
VDSO_SRCS=      $(VDSO_SRCDIR)/vdso.c $(VDSO_SRCDIR)/vdso-now.c
VDSO_OBJS=      $(patsubst $(ROOTDIR)/%.c,$(VDSO_OBJDIR)/%.o,$(VDSO_SRCS))
VDSO_CFLAGS=    -DBUILD_VDSO -I$(INCLUDES) -I$(OBJDIR) -fPIC -c
VDSO_LDFLAGS=   -nostdlib -fPIC -shared --build-id=none --hash-style=both --eh-frame-hdr -T$(VDSO_SRCDIR)/vdso.lds
VDSOGEN_SRC=    $(SRCDIR)/x86_64/vdsogen.c
VDSO_DEPS=      $(patsubst %.o,%.d,$(VDSO_OBJS))
OBJDUMPFLAGS=	-d -S -M intel-mnemonic

DEPFILES+=      $(VDSO_DEPS)
CLEANFILES+=    $(foreach f,gitversion.c frame.inc stage3.dis stage3.img src/unix/ftrace.* src/x86_64/ftrace.*,$(OBJDIR)/$f) $(VDSO_OBJDIR)/vdsogen $(VDSO_OBJDIR)/vdso.so $(VDSO_OBJDIR)/vdso-image.c $(VDSO_OBJS) $(VDSO_DEPS)
CLEANDIRS+=     $(foreach d,output src vdso/src/x86_64 vdso/src vdso vendor vendor/lwip vendor/lwip/src,$(OBJDIR)/$d)

msg_vdsogen_cc= CC	$@
cmd_vdsogen_cc= $(CC) -o $@ $^

msg_vdsogen=    VDSOGEN	$@
cmd_vdsogen=    $(VDSO_OBJDIR)/vdsogen $(VDSO_OBJDIR)/vdso.so $@

msg_vdso_cc=    CC	$@
cmd_vdso_cc=    $(CC) $(DEPFLAGS) $(VDSO_CFLAGS) -c $< -o $@

msg_vdso_ld=    LD	$@
cmd_vdso_ld=    $(LD) $(VDSO_LDFLAGS) $(VDSO_OBJS) -o $@ 

msg_objdump=	OBJDUMP	$@
cmd_objdump=	$(OBJDUMP) $(OBJDUMPFLAGS) $(OBJDUMPFLAGS_$(@F)) $< $< >$@

msg_sed=	SED	$@
cmd_sed=	$(SED) -e 's/\#/%/' <$^ >$@

msg_version=	VERSION	$@
cmd_version=	$(ECHO) "const char *gitversion = \"$(shell $(GIT) rev-parse HEAD)\";" >$@

all: stage3.dis

include ../rules.mk

.PHONY: stage3.dis

stage3.dis: $(OBJDIR)/stage3.dis

$(OBJDIR)/stage3.dis: $(PROG-stage3.img)
	$(call cmd,objdump)

$(VDSO_OBJDIR)/vdsogen: $(VDSOGEN_SRC)
	@$(MKDIR) $(VDSO_OBJDIR)
	$(call cmd,vdsogen_cc)

$(VDSO_OBJDIR)/src/x86_64/%.o: $(VDSO_SRCDIR)/%.c
	@$(MKDIR) $(dir $@)
	$(call cmd,vdso_cc)

$(VDSO_OBJDIR)/vdso.so: $(VDSO_OBJS)
	$(call cmd,vdso_ld)

$(VDSO_OBJDIR)/vdso-image.c: $(VDSO_OBJDIR)/vdsogen $(VDSO_OBJDIR)/vdso.so
	$(call cmd,vdsogen)

$(PROG-stage3.img): linker_script $(VDSO_OBJDIR)/vdso-image.c

$(OBJDIR)/gitversion.c: $(ROOTDIR)/.git/index $(ROOTDIR)/.git/HEAD
	$(call cmd,version)

$(OBJDIR)/src/x86_64/crt0.o: $(OBJDIR)/frame.inc

$(OBJDIR)/frame.inc: $(SRCDIR)/x86_64/frame.h
	$(call cmd,sed)

ifeq ($(UNAME_s),Darwin)
ELF_TARGET=     -target x86_64-elf
CFLAGS+=        $(ELF_TARGET)
VDSO_CFLAGS+=   $(ELF_TARGET)
VDSO_LDFLAGS+=  -undefined dynamic_lookup
LD=             x86_64-elf-ld
OBJDUMP=        x86_64-elf-objdump
else
LD=             ld
endif
