SUBDIR=		boot
LWIPDIR=	$(VENDORDIR)/lwip
PROGRAMS=	kernel.img

SRCS-kernel.img= \
	$(CURDIR)/service.c \
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
	$(SRCDIR)/kernel/backed_heap.c \
	$(SRCDIR)/kernel/elf.c \
	$(SRCDIR)/kernel/kernel.c \
	$(SRCDIR)/kernel/kvm_platform.c \
	$(SRCDIR)/kernel/pagecache.c \
	$(SRCDIR)/kernel/pci.c \
	$(SRCDIR)/kernel/pvclock.c \
	$(SRCDIR)/kernel/schedule.c \
	$(SRCDIR)/kernel/stage3.c \
	$(SRCDIR)/kernel/storage.c \
	$(SRCDIR)/kernel/symtab.c \
	$(SRCDIR)/kernel/vdso-now.c \
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
	$(SRCDIR)/unix/io_uring.c \
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
	$(SRCDIR)/virtio/virtio.c \
	$(SRCDIR)/virtio/virtio_mmio.c \
	$(SRCDIR)/virtio/virtio_net.c \
	$(SRCDIR)/virtio/virtio_pci.c \
	$(SRCDIR)/virtio/virtio_storage.c \
	$(SRCDIR)/virtio/virtio_scsi.c \
	$(SRCDIR)/virtio/virtqueue.c \
	$(SRCDIR)/virtio/scsi.c \
	$(SRCDIR)/vmware/vmxnet3_net.c \
	$(SRCDIR)/vmware/vmxnet3_queue.c \
	$(SRCDIR)/vmware/pvscsi.c \
	$(SRCDIR)/xen/xen.c \
	$(SRCDIR)/xen/xennet.c \
	$(SRCDIR)/hyperv/vmbus/hyperv.c \
	$(SRCDIR)/hyperv/vmbus/vmbus.c \
	$(SRCDIR)/hyperv/vmbus/vmbus_br.c \
	$(SRCDIR)/hyperv/vmbus/vmbus_chan.c \
	$(SRCDIR)/hyperv/vmbus/vmbus_xact.c \
	$(SRCDIR)/hyperv/vmbus/vmbus_et.c \
	$(SRCDIR)/hyperv/netvsc/netvsc.c \
	$(SRCDIR)/hyperv/netvsc/hv_net_vsc.c \
	$(SRCDIR)/hyperv/netvsc/hv_rndis_filter.c \
	$(SRCDIR)/hyperv/storvsc/storvsc.c \
	$(SRCDIR)/hyperv/utilities/vmbus_ic.c \
	$(SRCDIR)/hyperv/utilities/vmbus_shutdown.c \
	$(SRCDIR)/x86_64/ap.s \
	$(SRCDIR)/x86_64/apic.c \
	$(SRCDIR)/x86_64/breakpoint.c \
	$(SRCDIR)/x86_64/clock.c \
	$(SRCDIR)/x86_64/crt0.s \
	$(SRCDIR)/x86_64/flush.c \
	$(SRCDIR)/x86_64/hpet.c \
	$(SRCDIR)/x86_64/interrupt.c \
	$(SRCDIR)/x86_64/mp.c \
	$(SRCDIR)/x86_64/page.c \
	$(SRCDIR)/x86_64/rtc.c \
	$(SRCDIR)/x86_64/serial.c \
	$(SRCDIR)/x86_64/synth.c \
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
	-I$(ARCHDIR) \
	-I$(SRCDIR)/gdb \
	-I$(SRCDIR)/http \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/net \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/tfs \
	-I$(SRCDIR)/unix \
	-I$(SRCDIR)/unix_process \
	-I$(SRCDIR)/xen/public \
	-I$(SRCDIR)/hyperv/include \
	-I$(LWIPDIR)/src/include

AFLAGS+=-I$(ARCHDIR)/

CFLAGS+=$(KERNCFLAGS) -DSTAGE3 -DKERNEL -mcmodel=kernel
CFLAGS+=-Wno-address # lwIP build sadness
CFLAGS+=$(INCLUDES)

# Enable tracing by specifying TRACE=ftrace on command line
ifeq ($(TRACE),ftrace)
CFLAGS+= -DCONFIG_FTRACE -pg
SRCS-kernel.img+= \
	$(SRCDIR)/unix/ftrace.c \
	$(ARCHDIR)/ftrace.s
endif

#CFLAGS+=	-DLWIPDIR_DEBUG -DEPOLL_DEBUG -DNETSYSCALL_DEBUG -DKERNEL_DEBUG
AFLAGS+=	-felf64 -I$(OBJDIR)/
LDFLAGS+=	$(KERNLDFLAGS) --undefined=_start -T linker_script

VDSOGEN=	$(TOOLDIR)/vdsogen
VDSO_SRCDIR=    $(SRCDIR)/kernel
VDSO_OBJDIR=    $(OBJDIR)/vdso
VDSO_SRCS=      $(VDSO_SRCDIR)/vdso.c $(VDSO_SRCDIR)/vdso-now.c
VDSO_OBJS=      $(patsubst $(VDSO_SRCDIR)/%.c,$(VDSO_OBJDIR)/%.o,$(VDSO_SRCS))
VDSO_CFLAGS=    -DKERNEL -DBUILD_VDSO -I$(INCLUDES) -I$(OBJDIR) -I$(SRCDIR) -fPIC -c
VDSO_LDFLAGS=   -nostdlib -fPIC -shared --build-id=none --hash-style=both --eh-frame-hdr -T$(ARCHDIR)/vdso.lds
VDSO_DEPS=      $(patsubst %.o,%.d,$(VDSO_OBJS))
OBJDUMPFLAGS=	-d -S -M intel-mnemonic

DEPFILES+=      $(VDSO_DEPS)
CLEANFILES+=    $(foreach f,gitversion.c frame.inc kernel.dis kernel.img src/unix/ftrace.* $(ARCHDIR)/ftrace.*,$(OBJDIR)/$f) $(VDSO_OBJDIR)/vdso.so $(VDSO_OBJDIR)/vdso-image.c $(VDSO_OBJS) $(VDSO_DEPS)
CLEANDIRS+=     $(foreach d,output/platform output src src/hyperv vdso/src/$(ARCH) vdso/src vdso vendor vendor/lwip vendor/lwip/src platform,$(OBJDIR)/$d)

msg_vdsogen=    VDSOGEN	$@
cmd_vdsogen=    $(VDSOGEN) $(VDSO_OBJDIR)/vdso.so $@

msg_vdso_cc=    CC	$@
cmd_vdso_cc=    $(CC) $(DEPFLAGS) $(VDSO_CFLAGS) -c $< -o $@

msg_vdso_ld=    LD	$@
cmd_vdso_ld=    $(LD) $(VDSO_LDFLAGS) $(VDSO_OBJS) -o $@ 

msg_objdump=	OBJDUMP	$@
cmd_objdump=	$(OBJDUMP) $(OBJDUMPFLAGS) $(OBJDUMPFLAGS_$(@F)) $< $< >$@

msg_sed=	SED	$@
cmd_sed=	$(SED) -e 's/\#/%/' <$^ >$@

msg_version=	VERSION	$@
cmd_version=	$(MKDIR) $(dir $@); $(ECHO) "const char *gitversion = \"$(shell $(GIT) rev-parse HEAD)\";" >$@

include ../../rules.mk

MKFS=		$(TOOLDIR)/mkfs
BOOTIMG=	$(OBJDIR)/boot/boot.img
KERNEL=		$(OBJDIR)/bin/kernel.img

ifneq ($(ARCH),x86_64)
$(error The pc platform only supports the x86_64 architecture.)
endif

all: kernel.dis boot

mkfs vdsogen:
	$(Q) $(MAKE) -C $(ROOTDIR)/tools $@

boot:
	$(Q) $(MAKE) -C boot

kernel: $(PROG-kernel.img) $(OBJDIR)/kernel.dis

target:
ifeq ($(TARGET),)
	@echo TARGET variable not specified
	@false
endif
	$(Q) $(MAKE) -C $(ROOTDIR)/test/runtime $(TARGET)

ifneq ($(NANOS_TARGET_ROOT),)
TARGET_ROOT_OPT=	-r $(NANOS_TARGET_ROOT)
endif

image: mkfs boot kernel target
ifeq ($(IMAGE),)
	@echo IMAGE variable not specified
	@false
endif
	@ echo "MKFS	$@"
	@ $(MKDIR) $(dir $(IMAGE))
	$(Q) cd $(ROOTDIR); $(MKFS) $(TARGET_ROOT_OPT) -b $(BOOTIMG) -k $(KERNEL) $(IMAGE) < $(ROOTDIR)/test/runtime/$(TARGET).manifest

release: mkfs boot kernel
	$(Q) $(RM) -r release
	$(Q) $(MKDIR) release
	$(CP) $(MKFS) release
	$(CP) $(BOOTIMG) release
	$(CP) $(KERNEL) release
	cd release && $(TAR) -czvf nanos-release-$(REL_OS)-${version}.tar.gz *

.PHONY: mkfs vdsogen boot kernel target image release

$(VDSOGEN):
	@$(MAKE) -C $(ROOTDIR)/tools vdsogen

$(OBJDIR)/kernel.dis: $(PROG-kernel.img)
	$(call cmd,objdump)

$(VDSO_OBJDIR)/%.o: $(VDSO_SRCDIR)/%.c
	@$(MKDIR) $(dir $@)
	$(call cmd,vdso_cc)

$(VDSO_OBJDIR)/vdso.so: $(VDSO_OBJS)
	$(call cmd,vdso_ld)

$(VDSO_OBJDIR)/vdso-image.c: $(VDSOGEN) $(VDSO_OBJDIR)/vdso.so
	$(call cmd,vdsogen)

$(PROG-kernel.img): linker_script $(VDSO_OBJDIR)/vdso-image.c

$(OBJDIR)/gitversion.c: $(ROOTDIR)/.git/index $(ROOTDIR)/.git/HEAD
	$(call cmd,version)

$(OBJDIR)/src/$(ARCH)/crt0.o: $(OBJDIR)/frame.inc

$(OBJDIR)/frame.inc: $(ARCHDIR)/frame.h
	$(call cmd,sed)

ifeq ($(UNAME_s),Darwin)
ELF_TARGET=     -target x86_64-elf
CFLAGS+=        $(ELF_TARGET)
VDSO_CFLAGS+=   $(ELF_TARGET)
VDSO_LDFLAGS+=  -undefined dynamic_lookup
LD=             x86_64-elf-ld
OBJDUMP=        x86_64-elf-objdump
REL_OS=		darwin
QEMU_ACCEL=	-accel $(ACCEL) -cpu host
ACCEL?=		hvf
else
# XXX already defined?
LD=             $(CROSS_COMPILE)ld
REL_OS=		linux
QEMU_ACCEL=	-enable-kvm -cpu host
endif

##############################################################################
# run

.PHONY: run run-bridge run-nokvm

QEMU=		qemu-system-x86_64
MACHINE_TYPE=	q35
QEMU_CPU=	-cpu max
DISPLAY=	none
STORAGE=	virtio-scsi
STORAGE_BUS=	,bus=pci.2,addr=0x0
NETWORK=	virtio-net
NETWORK_BUS=	,bus=pci.3,addr=0x0

QEMU_MACHINE=	-machine $(MACHINE_TYPE)
QEMU_MEMORY=	-m 2G
QEMU_PCI=	-device pcie-root-port,port=0x10,chassis=1,id=pci.1,bus=$(PCI_BUS),multifunction=on,addr=0x3 \
		-device pcie-root-port,port=0x11,chassis=2,id=pci.2,bus=$(PCI_BUS),addr=0x3.0x1 \
		-device pcie-root-port,port=0x12,chassis=3,id=pci.3,bus=$(PCI_BUS),addr=0x3.0x2

ifeq ($(DISPLAY),none)
QEMU_DISPLAY=	-display none
else ifeq ($(DISPLAY),vga)
QEMU_DISPLAY=
else
$(error Unsupported DISPLAY=$(DISPLAY))
endif
QEMU_SERIAL=	-serial stdio
QEMU_STORAGE=	-drive if=none,id=hd0,format=raw,file=$(IMAGE)
ifeq ($(STORAGE),virtio-scsi)
QEMU_STORAGE+=	-device virtio-scsi-pci$(STORAGE_BUS),id=scsi0 -device scsi-hd,bus=scsi0.0,drive=hd0
else ifeq ($(STORAGE),pvscsi)
QEMU_STORAGE+=	-device pvscsi$(STORAGE_BUS),id=scsi0 -device scsi-hd,bus=scsi0.0,drive=hd0
else ifeq ($(STORAGE),virtio-blk)
QEMU_STORAGE+=	-device virtio-blk-pci$(STORAGE_BUS),drive=hd0
else ifeq ($(STORAGE),ide)
MACHINE_TYPE=	pc # no AHCI support yet
QEMU_STORAGE+=	-device ide-hd,bus=ide.0,drive=hd0
else
$(error Unsupported STORAGE=$(STORAGE))
endif
ifeq ($(MACHINE_TYPE),q35)
PCI_BUS=	pcie.0
else
PCI_BUS=	pci.0
endif
QEMU_TAP=	-netdev tap,id=n0,ifname=tap0,script=no,downscript=no
QEMU_NET=	-device $(NETWORK)$(NETWORK_BUS),mac=7e:b8:7e:87:4a:ea,netdev=n0 $(QEMU_TAP)
QEMU_USERNET=	-device $(NETWORK)$(NETWORK_BUS),netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=tcp::9090-:9090,hostfwd=udp::5309-:5309
#QEMU_USERNET+=	-object filter-dump,id=filter0,netdev=n0,file=/tmp/nanos.pcap
QEMU_FLAGS=
#QEMU_FLAGS+=	-smp 4
#QEMU_FLAGS+=	-d int -D int.log
#QEMU_FLAGS+=	-s -S

QEMU_COMMON=	$(QEMU_MACHINE) $(QEMU_MEMORY) $(QEMU_DISPLAY) $(QEMU_PCI) $(QEMU_SERIAL) $(QEMU_STORAGE) -device isa-debug-exit -no-reboot $(QEMU_FLAGS)

run: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) $(QEMU_ACCEL) || exit $$(($$?>>1))

run-bridge: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) $(QEMU_ACCEL) || exit $$(($$?>>1))

run-noaccel: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) $(QEMU_CPU) || exit $$(($$?>>1))
