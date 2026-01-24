include ../../vars.mk

SUBDIR=		boot
ACPICA_DIR=	$(VENDORDIR)/acpica
LWIPDIR=	$(VENDORDIR)/lwip
PROGRAMS=	kernel.elf

SRCS-kernel.elf= \
	$(CURDIR)/service.c \
	$(CURDIR)/pci.c \
	$(OBJDIR)/gitversion.c \
	$(ACPICA) \
	$(SRCDIR)/aws/ena/ena.c \
	$(SRCDIR)/aws/ena/ena_com/ena_com.c \
	$(SRCDIR)/aws/ena/ena_com/ena_eth_com.c \
	$(SRCDIR)/aws/ena/ena_datapath.c \
	$(SRCDIR)/drivers/acpi.c \
	$(SRCDIR)/drivers/ata.c \
	$(SRCDIR)/drivers/ata-pci.c \
	$(SRCDIR)/drivers/console.c \
	$(SRCDIR)/drivers/dmi.c \
	$(SRCDIR)/drivers/gve.c \
	$(SRCDIR)/drivers/nvme.c \
	$(SRCDIR)/drivers/netconsole.c \
	$(SRCDIR)/drivers/vga.c \
	$(SRCDIR)/gdb/gdbstub.c \
	$(SRCDIR)/gdb/gdbtcp.c \
	$(SRCDIR)/gdb/gdbutil.c \
	$(SRCDIR)/http/http.c \
	$(SRCDIR)/kernel/dma.c \
	$(SRCDIR)/kernel/elf.c \
	$(SRCDIR)/kernel/clock.c \
	$(SRCDIR)/kernel/flush.c \
	$(SRCDIR)/kernel/init.c \
	$(SRCDIR)/kernel/kernel.c \
	$(SRCDIR)/kernel/klib.c \
	$(SRCDIR)/kernel/kvm_platform.c \
	$(SRCDIR)/kernel/linear_backed_heap.c \
	$(SRCDIR)/kernel/locking_heap.c \
	$(SRCDIR)/kernel/log.c \
	$(SRCDIR)/kernel/ltrace.c \
	$(SRCDIR)/kernel/mutex.c \
	$(SRCDIR)/kernel/page.c \
	$(SRCDIR)/kernel/page_backed_heap.c \
	$(SRCDIR)/kernel/pagecache.c \
	$(SRCDIR)/kernel/pci.c \
	$(SRCDIR)/kernel/pvclock.c \
	$(SRCDIR)/kernel/schedule.c \
	$(SRCDIR)/kernel/stage3.c \
	$(SRCDIR)/kernel/storage.c \
	$(SRCDIR)/kernel/symtab.c \
	$(SRCDIR)/kernel/vdso-now.c \
	$(SRCDIR)/kernel/vmem_heap.c \
	$(SRCDIR)/net/direct.c \
	$(SRCDIR)/net/dhcp_option121.c \
	$(SRCDIR)/net/ip4_route_table.c \
	$(SRCDIR)/net/net.c \
	$(SRCDIR)/net/netsyscall.c \
	$(RUNTIME) \
	$(SRCDIR)/fs/9p.c \
	$(SRCDIR)/fs/fs.c \
	$(SRCDIR)/fs/tfs.c \
	$(SRCDIR)/fs/tlog.c \
	$(SRCDIR)/unix/aio.c \
	$(SRCDIR)/unix/blockq.c \
	$(SRCDIR)/unix/coredump.c \
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
	$(SRCDIR)/unix/vdso.c \
	$(SRCDIR)/unix/vsock.c \
	$(SRCDIR)/unix/pipe.c \
	$(SRCDIR)/virtio/virtio.c \
	$(SRCDIR)/virtio/virtio_9p.c \
	$(SRCDIR)/virtio/virtio_balloon.c \
	$(SRCDIR)/virtio/virtio_mmio.c \
	$(SRCDIR)/virtio/virtio_net.c \
	$(SRCDIR)/virtio/virtio_pci.c \
	$(SRCDIR)/virtio/virtio_rng.c \
	$(SRCDIR)/virtio/virtio_storage.c \
	$(SRCDIR)/virtio/virtio_scsi.c \
	$(SRCDIR)/virtio/virtio_socket.c \
	$(SRCDIR)/virtio/virtqueue.c \
	$(SRCDIR)/virtio/scsi.c \
	$(SRCDIR)/vmware/vmxnet3_net.c \
	$(SRCDIR)/vmware/vmxnet3_queue.c \
	$(SRCDIR)/vmware/pvscsi.c \
	$(SRCDIR)/xen/xen.c \
	$(SRCDIR)/xen/xenblk.c \
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
	$(SRCDIR)/x86_64/acpi.c \
	$(SRCDIR)/x86_64/apic.c \
	$(SRCDIR)/x86_64/breakpoint.c \
	$(SRCDIR)/x86_64/clock.c \
	$(SRCDIR)/x86_64/crt0.s \
	$(SRCDIR)/x86_64/elf64.c \
	$(SRCDIR)/x86_64/hpet.c \
	$(SRCDIR)/x86_64/hyperv.c \
	$(SRCDIR)/x86_64/init.s \
	$(SRCDIR)/x86_64/interrupt.c \
	$(SRCDIR)/x86_64/kernel_machine.c \
	$(SRCDIR)/x86_64/mp.c \
	$(SRCDIR)/x86_64/page.c \
	$(SRCDIR)/x86_64/pvm.c \
	$(SRCDIR)/x86_64/pvm_asm.s \
	$(SRCDIR)/x86_64/rtc.c \
	$(SRCDIR)/x86_64/serial.c \
	$(SRCDIR)/x86_64/synth.c \
	$(SRCDIR)/x86_64/unix_machine.c \
	$(SRCDIR)/x86_64/x2apic.c \
	$(SRCDIR)/x86_64/xapic.c \
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
	-I$(SRCDIR)/gdb \
	-I$(SRCDIR)/http \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/net \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/fs \
	-I$(SRCDIR)/unix \
	-I$(SRCDIR)/unix_process \
	-I$(SRCDIR)/xen/public \
	-I$(SRCDIR)/hyperv/include \
	-I$(ACPICA_DIR)/source/include \
	-I$(LWIPDIR)/src/include \

AFLAGS+=-I$(ARCHDIR)/

CFLAGS+=-DCONFIG_LTRACE
CFLAGS+=-DDMA_BUFFERING	# required by memory encryption

AFLAGS+=	-felf64 -I$(OBJDIR)/

OBJDUMPFLAGS=	-d -S -M intel-mnemonic

DEPFILES+=      $(VDSO_DEPS)
CLEANFILES+=    $(foreach f,gitversion.c frame.inc kernel.dis kernel.elf src/unix/ftrace.* $(ARCHDIR)/ftrace.*,$(OBJDIR)/$f) $(VDSO_OBJDIR)/vdso.so $(VDSO_OBJDIR)/vdso-image.c $(VDSO_OBJS) $(VDSO_DEPS) $(KERNEL)
CLEANDIRS+=     $(foreach d,output/platform output src/aws src/hyperv vdso/src/$(ARCH) vdso/src vdso vendor vendor/lwip vendor/lwip/src vendor/lwip/src/netif vendor/lwip/src/netif/ppp vendor/acpica vendor/acpica/source vendor/acpica/source/components platform,$(OBJDIR)/$d)

MKFS=		$(TOOLDIR)/mkfs
BOOTIMG=	$(OBJDIR)/boot/boot.img
KERNEL=		$(OBJDIR)/bin/kernel.img

include ../../kernel.mk

ifneq ($(ARCH),x86_64)
$(error The pc platform only supports the x86_64 architecture.)
endif

all: kernel.dis boot

boot:
	$(Q) $(MAKE) -C boot

kernel: $(KERNEL)

kernel.dis: $(KERNEL) $(OBJDIR)/kernel.dis

ifneq ($(ENABLE_UEFI),)
MKFS_UEFI=	-u $(OBJDIR)/boot/bootx64.efi
endif

image: mkfs boot $(DEFAULT_KERNEL_TARGET) target
ifeq ($(IMAGE),)
	@echo IMAGE variable not specified
	@false
endif
	@ echo "MKFS	$@"
	@ $(MKDIR) $(dir $(IMAGE))
	$(Q) cd $(ROOTDIR); \
		$(AWK) 'BEGIN{getline l < "$(PLATFORMDIR)/test-libs"}/TEST-LIBS/{gsub("TEST-LIBS",l)}/ARCH_DIR/{gsub("ARCH_DIR","$(PLATFORMOBJDIR)")}1' $(ROOTDIR)/test/runtime/$(TARGET).manifest | \
		$(MKFS) $(TARGET_ROOT_OPT) -b $(BOOTIMG) $(MKFS_UEFI) -k $(KERNEL) -t "(debug_exit:t)" $(TRACELOG_MKFS_OPTS) $(EXTRA_MKFS_OPTS) $(IMAGE)

$(OBJDIR)/src/$(ARCH)/crt0.o \
$(OBJDIR)/src/$(ARCH)/pvm_asm.o \
$(OBJDIR)/src/$(ARCH)/frtace.o \
: $(OBJDIR)/frame.inc

$(OBJDIR)/frame.inc: $(ARCHDIR)/frame.h
	$(call cmd,sed)

ifeq ($(UNAME_s),Darwin)
VDSO_LDFLAGS+=  -undefined dynamic_lookup
REL_OS=		darwin
# disable rdtscp as a workaround on mac since it can't pass the instruction through
# see https://bugs.launchpad.net/qemu/+bug/1894836
QEMU_ACCEL=	-accel $(ACCEL) -cpu host,-rdtscp
ACCEL?=		hvf
else
REL_OS=		linux
QEMU_ACCEL=	-enable-kvm -cpu host
endif
LD=             $(CROSS_COMPILE)ld

##############################################################################
# run

.PHONY: run run-bridge run-nokvm

QEMU=		qemu-system-x86_64
QEMU_FLAGS=
ifneq ($(MICROVM),)
IOAPIC2=	$(shell $(QEMU) -machine microvm,help | grep -c ioapic2)
ifneq ($(IOAPIC2),0)
MACHINE_TYPE=	microvm,rtc=on,ioapic2=off
else
MACHINE_TYPE=	microvm,rtc=on
endif
KERNEL_BOOT=	1
STORAGE=	virtio-mmio
NETWORK=	virtio-net-device
QEMU_FLAGS+=	-global virtio-mmio.force-legacy=false
else
MACHINE_TYPE=	q35
STORAGE=	virtio-scsi
STORAGE_BUS=	,bus=pci.2,addr=0x0
NETWORK=	virtio-net
NETWORK_BUS=	,bus=pci.3,addr=0x0
NETWORK_BUS_2=  ,bus=pci.3,addr=0x1
QEMU_RNG=	-device virtio-rng-pci
QEMU_PCI=	-device pcie-root-port,port=0x10,chassis=1,id=pci.1,bus=$(PCI_BUS),multifunction=on,addr=0x3 \
		-device pcie-root-port,port=0x11,chassis=2,id=pci.2,bus=$(PCI_BUS),addr=0x3.0x1 \
		-device pcie-root-port,port=0x12,chassis=3,id=pci.3,bus=$(PCI_BUS),addr=0x3.0x2
endif
QEMU_CPU=	-cpu max
DISPLAY=	none
QEMU_MACHINE=	-machine $(MACHINE_TYPE)
QEMU_MEMORY=	-m 2G
ifneq ($(KERNEL_BOOT),)
QEMU_FLAGS+=	-kernel $(KERNEL)
endif

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
else ifeq ($(STORAGE),virtio-mmio)
QEMU_STORAGE+=	-device virtio-blk-device,drive=hd0
else ifeq ($(STORAGE),ide)
MACHINE_TYPE=	pc # no AHCI support yet
QEMU_STORAGE+=	-device ide-hd,bus=ide.0,drive=hd0
else
$(error Unsupported STORAGE=$(STORAGE))
endif
ifneq ($(VIRTFS),)
QEMU_STORAGE+= -virtfs local,path=$(VIRTFS),mount_tag=1,security_model=none,id=hd1
endif
ifeq ($(MACHINE_TYPE),q35)
PCI_BUS=	pcie.0
else
PCI_BUS=	pci.0
endif
QEMU_TAP=	-netdev tap,id=n0,ifname=tap0,script=no,downscript=no
QEMU_NET=	-device $(NETWORK)$(NETWORK_BUS),mac=7e:b8:7e:87:4a:ea,netdev=n0 $(QEMU_TAP)
QEMU_USERNET=	-device $(NETWORK)$(NETWORK_BUS),netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=tcp::9090-:9090,hostfwd=udp::5309-:5309
ifneq ($(ENABLE_SECOND_IFACE),)
QEMU_NET+=	-device $(NETWORK)$(NETWORK_BUS_2),mac=7e:b8:7e:87:4b:ea,netdev=n1 -netdev tap,id=n1,ifname=tap1,script=no,downscript=no
QEMU_USERNET+=  -device $(NETWORK)$(NETWORK_BUS_2),netdev=n1 -netdev user,id=n1
endif
ifneq ($(ENABLE_BALLOON),)
QEMU_BALLOON=   -device virtio-balloon-pci
endif
ifneq ($(ENABLE_QMP),)
QEMU_QMP=	-qmp unix:$(ROOTDIR)/qmp-sock,server,nowait
#QEMU_QMP=	-qmp tcp:localhost:4444,server,nowait
endif
#QEMU_USERNET+=	-object filter-dump,id=filter0,netdev=n0,file=/tmp/nanos.pcap
ifneq ($(VCPUS),)
QEMU_FLAGS+=	-smp $(VCPUS)
endif
#QEMU_FLAGS+=	-d int -D int.log
#QEMU_FLAGS+=	-s -S

QEMU_COMMON=	$(QEMU_MACHINE) $(QEMU_MEMORY) $(QEMU_BALLOON) $(QEMU_DISPLAY) $(QEMU_PCI) $(QEMU_RNG) $(QEMU_SERIAL) $(QEMU_STORAGE) -device isa-debug-exit -no-reboot $(QEMU_FLAGS) $(QEMU_QMP)

run:
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) $(QEMU_ACCEL) || exit $$(($$?>>1))

run-bridge:
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) $(QEMU_ACCEL) || exit $$(($$?>>1))

run-noaccel:
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) $(QEMU_CPU) || exit $$(($$?>>1))
