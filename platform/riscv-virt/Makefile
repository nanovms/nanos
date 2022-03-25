LWIPDIR=	$(VENDORDIR)/lwip
PROGRAMS=	kernel.elf

# XXX temp
WITHOUT_SSP=	1

SRCS-kernel.elf= \
	$(CURDIR)/service.c \
	$(CURDIR)/pci.c \
	$(OBJDIR)/gitversion.c \
	$(SRCDIR)/riscv64/crt0.S \
	$(SRCDIR)/riscv64/clock.c \
	$(SRCDIR)/riscv64/elf64.c \
	$(SRCDIR)/riscv64/kernel_machine.c \
	$(SRCDIR)/riscv64/interrupt.c \
	$(SRCDIR)/riscv64/page.c \
	$(SRCDIR)/riscv64/plic.c \
	$(SRCDIR)/riscv64/serial.c \
	$(SRCDIR)/riscv64/unix_machine.c \
	$(SRCDIR)/drivers/console.c \
	$(SRCDIR)/drivers/netconsole.c \
	$(SRCDIR)/gdb/gdbstub.c \
	$(SRCDIR)/gdb/gdbtcp.c \
	$(SRCDIR)/gdb/gdbutil.c \
	$(SRCDIR)/http/http.c \
	$(SRCDIR)/kernel/elf.c \
	$(SRCDIR)/kernel/clock.c \
	$(SRCDIR)/kernel/init.c \
	$(SRCDIR)/kernel/kernel.c \
	$(SRCDIR)/kernel/klib.c \
	$(SRCDIR)/kernel/linear_backed_heap.c \
	$(SRCDIR)/kernel/locking_heap.c \
	$(SRCDIR)/kernel/log.c \
	$(SRCDIR)/kernel/mutex.c \
	$(SRCDIR)/kernel/page.c \
	$(SRCDIR)/kernel/page_backed_heap.c \
	$(SRCDIR)/kernel/pagecache.c \
	$(SRCDIR)/kernel/pci.c \
	$(SRCDIR)/kernel/schedule.c \
	$(SRCDIR)/kernel/stage3.c \
	$(SRCDIR)/kernel/storage.c \
	$(SRCDIR)/kernel/symtab.c \
	$(SRCDIR)/kernel/vdso-now.c \
	$(SRCDIR)/net/direct.c \
	$(SRCDIR)/net/net.c \
	$(SRCDIR)/net/netsyscall.c \
	$(RUNTIME) \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c \
	$(SRCDIR)/unix/aio.c \
	$(SRCDIR)/unix/blockq.c \
	$(SRCDIR)/unix/exec.c \
	$(SRCDIR)/unix/eventfd.c \
	$(SRCDIR)/unix/filesystem.c \
	$(SRCDIR)/unix/futex.c \
	$(SRCDIR)/unix/inotify.c \
	$(SRCDIR)/unix/io_uring.c \
	$(SRCDIR)/unix/mktime.c \
	$(SRCDIR)/unix/mmap.c \
	$(SRCDIR)/unix/netlink.c \
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
	$(SRCDIR)/unix/pipe.c \
	$(SRCDIR)/unix/vdso.c \
	$(SRCDIR)/virtio/virtio.c \
	$(SRCDIR)/virtio/virtio_balloon.c \
	$(SRCDIR)/virtio/virtio_mmio.c \
	$(SRCDIR)/virtio/virtio_net.c \
	$(SRCDIR)/virtio/virtio_pci.c \
	$(SRCDIR)/virtio/virtio_scsi.c \
	$(SRCDIR)/virtio/virtio_storage.c \
	$(SRCDIR)/virtio/virtqueue.c \
	$(SRCDIR)/virtio/scsi.c \
	$(VDSO_OBJDIR)/vdso-image.c \
	$(SRCS-lwip)


SRCS-lwip= \
	$(LWIPDIR)/src/core/def.c \
	$(LWIPDIR)/src/core/dns.c \
	$(LWIPDIR)/src/core/inet_chksum.c \
	$(LWIPDIR)/src/core/init.c \
	$(LWIPDIR)/src/core/ip.c \
	$(LWIPDIR)/src/core/ipv4/dhcp.c \
	$(LWIPDIR)/src/core/ipv4/etharp.c \
	$(LWIPDIR)/src/core/ipv4/icmp.c \
	$(LWIPDIR)/src/core/ipv4/ip4_addr.c \
	$(LWIPDIR)/src/core/ipv4/ip4_frag.c \
	$(LWIPDIR)/src/core/ipv4/ip4.c \
	$(LWIPDIR)/src/core/ipv6/dhcp6.c \
	$(LWIPDIR)/src/core/ipv6/ethip6.c \
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
	$(LWIPDIR)/src/netif/ethernet.c \
	$(LWIPDIR)/src/netif/ppp/polarssl/md5.c \

INCLUDES=\
	-I$(SRCDIR) \
	-I$(ARCHDIR) \
	-I$(CURDIR) \
	-I$(SRCDIR)/gdb \
	-I$(SRCDIR)/http \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/net \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/tfs \
	-I$(SRCDIR)/unix \
	-I$(SRCDIR)/unix_process \
	-I$(SRCDIR)/xen/public \
	-I$(LWIPDIR)/src/include \
	-I$(VDSO_OBJDIR) \
	-I$(OUTDIR)

AFLAGS+=-I$(ARCHDIR) -march=rv64gc -mabi=lp64d

CFLAGS+=$(KERNCFLAGS) -DKERNEL -O3 -march=rv64gc -mabi=lp64d -fno-pic
CFLAGS+=-Wno-address # lwIP build sadness
CFLAGS+=$(INCLUDES)

# Enable tracing by specifying TRACE=ftrace on command line
ifeq ($(TRACE),ftrace)
CFLAGS+= -DCONFIG_FTRACE -pg
SRCS-kernel.elf+= \
	$(SRCDIR)/unix/ftrace.c \
	$(ARCHDIR)/ftrace.s
endif

ifeq ($(TRACE),tracelog)
CFLAGS+= -DCONFIG_TRACELOG
SRCS-kernel.elf+= \
	$(SRCDIR)/kernel/tracelog.c
endif

ifeq ($(MANAGEMENT),telnet)
CFLAGS+= -DMANAGEMENT_TELNET
SRCS-kernel.elf+= \
	$(SRCDIR)/kernel/management_telnet.c
endif

#CFLAGS+=	-DLWIPDIR_DEBUG -DEPOLL_DEBUG -DNETSYSCALL_DEBUG -DKERNEL_DEBUG
AFLAGS+=	-I$(OBJDIR)/
LDFLAGS+=	$(KERNLDFLAGS) --undefined=_start -T linker_script

VDSOGEN=	$(TOOLDIR)/vdsogen
VDSO_SRCDIR=    $(SRCDIR)/kernel
VDSO_OBJDIR=    $(OBJDIR)/vdso
VDSO_SRCS=      $(VDSO_SRCDIR)/vdso.c $(VDSO_SRCDIR)/vdso-now.c
VDSO_OBJS=      $(patsubst $(VDSO_SRCDIR)/%.c,$(VDSO_OBJDIR)/%.o,$(VDSO_SRCS))
VDSO_CFLAGS=    -DKERNEL -DBUILD_VDSO -I$(INCLUDES) -I$(OBJDIR) -I$(SRCDIR) -fPIC -c
VDSO_LDFLAGS=   -nostdlib -fPIC -shared --build-id=none --hash-style=both --eh-frame-hdr -T$(ARCHDIR)/vdso.lds
VDSO_DEPS=      $(patsubst %.o,%.d,$(VDSO_OBJS))
OBJDUMPFLAGS=	-d -S
STRIPFLAGS=	-g

DEPFILES+=      $(VDSO_DEPS)
CLEANFILES+=    $(foreach f,gitversion.c frame.inc kernel.dis bin/kernel.elf src/unix/ftrace.* $(ARCHDIR)/ftrace.*,$(OBJDIR)/$f) $(VDSO_OBJDIR)/vdso.so $(VDSO_OBJDIR)/vdso-image.c $(VDSO_OBJDIR)/vdso-offset.h $(VDSO_OBJS) $(VDSO_DEPS) $(BOOTIMG) $(KERNEL)
CLEANDIRS+=     $(foreach d,output/platform output src vdso/src/$(ARCH) vdso/src vdso vendor vendor/lwip vendor/lwip/src vendor/lwip/src/netif vendor/lwip/src/netif/ppp platform,$(OBJDIR)/$d)

OBJCOPYFLAGS	= -S -O binary

msg_vdsogen=    VDSOGEN	$@
cmd_vdsogen=    $(VDSOGEN) $(VDSO_OBJDIR)/vdso.so $@

msg_vdso_cc=    CC	$@
cmd_vdso_cc=    $(CC) $(DEPFLAGS) $(VDSO_CFLAGS) -c $< -o $@

msg_vdso_ld=    LD	$@
cmd_vdso_ld=    $(LD) $(VDSO_LDFLAGS) $(VDSO_OBJS) -o $@ 

msg_objdump=	OBJDUMP	$@
cmd_objdump=	$(OBJDUMP) $(OBJDUMPFLAGS) $(OBJDUMPFLAGS_$(@F)) $< $< >$@

msg_objcopy=	OBJCOPY	$@
cmd_objcopy=	$(OBJCOPY) $(OBJCOPYFLAGS) $(OBJCOPYFLAGS_$(@F)) $< $@

msg_sed=	SED	$@
cmd_sed=	$(SED) -e 's/\#/%/' <$^ >$@

msg_version=	VERSION	$@
cmd_version=	$(MKDIR) $(dir $@); $(ECHO) "const char *gitversion = \"$(shell $(GIT) rev-parse HEAD)\";" >$@

msg_xxd_r=	XXD_R	$@
cmd_xxd_r=	$(XXD) -r $< $@

include ../../rules.mk

# check riscv64 gcc version for 9.3.0, lowest known working version (from Ubuntu 20)
GCCRAWVER= $(shell $(CC) -dumpfullversion -dumpversion)
GCCVER= $(shell echo $(GCCRAWVER) | awk -F'.' '{ printf "%02d%02d%02d", $$1, $$2, $$3 }')
GCCOK= $(shell expr $(GCCVER) \>= 090300)
ifeq ($(GCCOK), 0)
$(error gcc version 9.3.0 or higher required to build RISC-V: $(CC) is only $(GCCRAWVER))
endif

MKFS=		$(TOOLDIR)/mkfs
BOOTIMG=	$(OBJDIR)/boot-stub.img
KERNEL=		$(OBJDIR)/bin/kernel.img

ifneq ($(ARCH),riscv64)
$(error The riscv platform only supports the riscv64 architecture.)
endif

all: $(KERNEL) kernel.dis

mkfs vdsogen:
	$(Q) $(MAKE) -C $(ROOTDIR)/tools $@

kernel: $(KERNEL) $(OBJDIR)/kernel.dis

target:
ifeq ($(TARGET),)
	@echo TARGET variable not specified
	@false
endif
	$(Q) $(MAKE) -C $(ROOTDIR)/test/runtime $(TARGET)

ifneq ($(NANOS_TARGET_ROOT),)
TARGET_ROOT_OPT=	-r $(NANOS_TARGET_ROOT)
endif

image: mkfs kernel target $(BOOTIMG)
ifeq ($(IMAGE),)
	@echo IMAGE variable not specified
	@false
endif
	@ echo "MKFS	$@"
	@ $(MKDIR) $(dir $(IMAGE))
	$(Q) cd $(ROOTDIR); $(AWK) 'BEGIN{getline l < "$(PLATFORMDIR)/test-libs"}/TEST-LIBS/{gsub("TEST-LIBS",l)}1' $(ROOTDIR)/test/runtime/$(TARGET).manifest | $(MKFS) $(TARGET_ROOT_OPT) -b $(BOOTIMG) -k $(KERNEL) $(IMAGE)

release: mkfs kernel
	$(Q) $(RM) -r release
	$(Q) $(MKDIR) release
	$(CP) $(MKFS) release
	$(CP) $(KERNEL) release
	cd release && $(TAR) -czvf nanos-release-$(REL_OS)-${version}.tar.gz *

.PHONY: mkfs vdsogen kernel target image release

$(VDSOGEN):
	@$(MAKE) -C $(ROOTDIR)/tools vdsogen

$(OBJDIR)/kernel.dis: $(KERNEL)
	$(call cmd,objdump)

$(VDSO_OBJDIR)/%.o: $(VDSO_SRCDIR)/%.c
	@$(MKDIR) $(dir $@)
	$(call cmd,vdso_cc)

$(VDSO_OBJDIR)/vdso.so: $(VDSO_OBJS)
	$(call cmd,vdso_ld)

$(VDSO_OBJDIR)/vdso-image.c: $(VDSOGEN) $(VDSO_OBJDIR)/vdso.so
	$(call cmd,vdsogen)

$(VDSO_OBJDIR)/vdso-offset.h: $(VDSO_OBJDIR)/vdso.so
	$(Q) $(OBJDUMP) -t $(VDSO_OBJDIR)/vdso.so | grep __vdso_rt_sigreturn | sed "s/^\([[:xdigit:]]*\) .*/#define VDSO_OFFSET_RT_SIGRETURN 0x\1/" > $@

$(OBJDIR)/src/$(ARCH)/unix_machine.o: $(VDSO_OBJDIR)/vdso-offset.h

$(PROG-kernel.elf): linker_script $(OUTDIR)/klib/klib-syms.lds $(VDSO_OBJDIR)/vdso-image.c

$(KERNEL): $(PROG-kernel.elf)
	$(call cmd,strip)

$(OBJDIR)/gitversion.c: $(ROOTDIR)/.git/index $(ROOTDIR)/.git/HEAD
	$(call cmd,version)

$(BOOTIMG): mbr.hex
	$(call cmd,xxd_r)

LD=             $(CROSS_COMPILE)ld
REL_OS=		linux
QEMU_ACCEL=	-enable-kvm -cpu host

##############################################################################
# run

.PHONY: run run-bridge run-nokvm

QEMU=		$(QEMU_PATH)qemu-system-riscv64
QEMU_CPU=	-cpu rv64
DISPLAY=	none
STORAGE=	virtio-blk
NETWORK=	virtio-net

QEMU_MACHINE=	-machine virt
QEMU_MEMORY=	-m 1G
PCI_BUS=	pcie.0
QEMU_KERNEL=	-kernel $(KERNEL)

QEMU_DISPLAY=	-display none
#QEMU_DISPLAY=	-nographic
QEMU_SERIAL=	-serial stdio
QEMU_STORAGE=	-drive if=none,id=hd0,format=raw,file=$(IMAGE)
ifeq ($(STORAGE),virtio-scsi)
QEMU_STORAGE+=	-device virtio-scsi-device,id=scsi0 -device scsi-hd,bus=scsi0.0,drive=hd0
else ifeq ($(STORAGE),pvscsi)
QEMU_STORAGE+=	-device pvscsi$(STORAGE_BUS),id=scsi0 -device scsi-hd,bus=scsi0.0,drive=hd0
else ifeq ($(STORAGE),virtio-blk)
QEMU_STORAGE+=	-device virtio-blk-pci$(STORAGE_BUS),drive=hd0
else
$(error Unsupported STORAGE=$(STORAGE))
endif
QEMU_TAP=	-netdev tap,id=n0,ifname=tap0,script=no,downscript=no
#QEMU_NET=	-device $(NETWORK)$(NETWORK_BUS),mac=7e:b8:7e:87:4a:ea,netdev=n0,modern-pio-notify $(QEMU_TAP)
QEMU_NET=	-device $(NETWORK)$(NETWORK_BUS),mac=7e:b8:7e:87:4a:ea,netdev=n0 $(QEMU_TAP)
QEMU_USERNET=	-device $(NETWORK)$(NETWORK_BUS),netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=tcp::9090-:9090,hostfwd=udp::5309-:5309 -object filter-dump,id=filter0,netdev=n0,file=/tmp/nanos.pcap
ifneq ($(ENABLE_BALLOON),)
QEMU_BALLOON=   -device virtio-balloon-pci
endif
ifneq ($(ENABLE_QMP),)
QEMU_QMP=	-qmp unix:$(ROOTDIR)/qmp-sock,server,nowait
#QEMU_QMP=	-qmp tcp:localhost:4444,server,nowait
endif

# various combinations of flags that are usefull when debugging
#QEMU_FLAGS+=   -machine dumpdtb=riscv.dtb
#QEMU_FLAGS+=	-d in_asm,cpu -D $(ROOTDIR)/asm.out
#QEMU_FLAGS+=	-d int -D int
#QEMU_FLAGS+=	-s -S
#QEMU_FLAGS+=   -d int,trace:pci_cfg_write,trace:pci_cfg_read,trace:msix_write_config,trace:virtio_blk_req_complete,trace:virtio_blk_rw_complete,trace:virtio_blk_handle_read,trace:virtio_blk_handle_write,trace:virtio_blk_submit_multireq,trace:virtio_blk_handle_write,trace:virtio_blk_handle_read,trace:virtio_blk_submit_multireq,trace:virtio_queue_notify,trace:virtio_notify,trace:virtio_set_status,trace:virtio_notify_irqfd,guest_errors,trace:virtio_blk_data_plane_start,trace:virtio_input_queue_full,trace:kvm_irqchip_commit_routes,trace:kvm_irqchip_add_msi_route,trace:kvm_irqchip_update_msi_route,trace:kvm_irqchip_release_virq,trace:kvm_set_ioeventfd_mmio,trace:kvm_set_ioeventfd_pio,trace:kvm_set_user_memory,trace:kvm_clear_dirty_log,trace:kvm_resample_fd_notify,trace:kvm_run_exit,trace:kvm_ioctl,trace:kvm_vm_ioctl,trace:kvm_vcpu_ioctl,trace:kvm_device_ioctl -D $(ROOTDIR)/trace.out

#QEMU_FLAGS+=	-monitor telnet:127.0.0.1:9999,server,nowait

QEMU_COMMON=	$(QEMU_MACHINE) $(QEMU_MEMORY) $(QEMU_BALLOON) $(QEMU_KERNEL) $(QEMU_DISPLAY) $(QEMU_PCI) $(QEMU_SERIAL) $(QEMU_STORAGE) -no-reboot $(QEMU_FLAGS) $(QEMU_QMP)

run: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) $(QEMU_ACCEL)

run-bridge: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) $(QEMU_CPU)

run-noaccel: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) $(QEMU_CPU)
