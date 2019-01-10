include ../config.mk
include ../common.mk

OUT		?= $(ROOT)/output/stage3
AFLAGS		= -felf64
CFLAGS 		+= -DSTAGE3
LDFLAGS 	+= -n -T linker_script -nostdlib
OBJDUMPFLAGS	+= -d -S
GITFLAGS	+= --depth 1 http://git.savannah.nongnu.org/git/lwip.git -b STABLE-2_0_3_RELEASE

#CFLAGS = -DLWIP_DEBUG -DEPOLL_DEBUG -DNETSYSCALL_DEBUG -DKERNEL_DEBUG

all: stage3

stage3: $(STAGE3)

lwip: $(LWIP)/.vendored

includes = \
	-I$(SRC)/gdb \
	-I$(SRC)/net \
	-I$(SRC)/runtime \
	-I$(SRC)/tfs \
	-I$(SRC)/unix \
	-I$(SRC)/virtio \
	-I$(SRC)/x86_64 \
	-I$(LWIP)/src/include \

stage3-srcs = \
	$(ROOT)/stage3/stage3.c \
	$(SRC)/gdb/gdbstub.c \
	$(SRC)/gdb/gdbtcp.c \
	$(SRC)/gdb/gdbutil.c \
	$(SRC)/net/net.c \
	$(SRC)/net/netsyscall.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/freelist.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/heap/mcache.c \
	$(SRC)/runtime/heap/objcache.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/sha256.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix/blockq.c \
	$(SRC)/unix/exec.c \
	$(SRC)/unix/mktime.c \
	$(SRC)/unix/mmap.c \
	$(SRC)/unix/poll.c \
	$(SRC)/unix/path.c \
	$(SRC)/unix/signal.c \
	$(SRC)/unix/special.c \
	$(SRC)/unix/syscall.c \
	$(SRC)/unix/thread.c \
	$(SRC)/unix/unix_clock.c \
	$(SRC)/unix/unix.c \
	$(SRC)/unix/vdso.c \
	$(SRC)/unix/pipe.c \
	$(SRC)/virtio/virtio_net.c \
	$(SRC)/virtio/virtio_pci.c \
	$(SRC)/virtio/virtio_storage.c \
	$(SRC)/virtio/virtqueue.c \
	$(SRC)/x86_64/backed_heap.c \
	$(SRC)/x86_64/breakpoint.c \
	$(SRC)/x86_64/clock.c \
	$(SRC)/x86_64/crt0.s \
	$(SRC)/x86_64/elf.c \
	$(SRC)/x86_64/hpet.c \
	$(SRC)/x86_64/interrupt.c \
	$(SRC)/x86_64/kvm_platform.c \
	$(SRC)/x86_64/page.c \
	$(SRC)/x86_64/pci.c \
	$(SRC)/x86_64/queue.c \
	$(SRC)/x86_64/rtc.c \
	$(SRC)/x86_64/serial.c \
	$(SRC)/x86_64/service.c \
	$(SRC)/x86_64/symtab.c \
	$(SRC)/x86_64/synth.c \
	$(LWIP)/src/core/def.c \
	$(LWIP)/src/core/inet_chksum.c \
	$(LWIP)/src/core/init.c \
	$(LWIP)/src/core/ip.c \
	$(LWIP)/src/core/ipv4/dhcp.c \
	$(LWIP)/src/core/ipv4/etharp.c \
	$(LWIP)/src/core/ipv4/icmp.c \
	$(LWIP)/src/core/ipv4/ip4_addr.c \
	$(LWIP)/src/core/ipv4/ip4_frag.c \
	$(LWIP)/src/core/ipv4/ip4.c \
	$(LWIP)/src/core/mem.c \
	$(LWIP)/src/core/memp.c \
	$(LWIP)/src/core/netif.c \
	$(LWIP)/src/core/pbuf.c \
	$(LWIP)/src/core/stats.c \
	$(LWIP)/src/core/tcp_in.c \
	$(LWIP)/src/core/tcp_out.c \
	$(LWIP)/src/core/tcp.c \
	$(LWIP)/src/core/timeouts.c \
	$(LWIP)/src/core/udp.c \
	$(LWIP)/src/api/err.c \
	$(LWIP)/src/netif/ethernet.c

stage3-objs = $(call srcs-to-objs,$(ROOT),$(OUT),stage3)

$(stage3-srcs): | lwip

$(stage3-objs): $(stage3-srcs) $(CLOSURE_TMPL)

$(STAGE3): $(stage3-objs)
	$(call cmd,ld)
	$(call cmd,objdump)

$(OUT)/src/x86_64/crt0.o: AFLAGS += -I$(OUT)/x86_64/
$(OUT)/src/x86_64/crt0.o: $(OUT)/x86_64/frame_nasm.h

$(OUT)/x86_64/frame_nasm.h: $(SRC)/x86_64/frame.h
	@ echo "SED	$@"
	@ mkdir -p $(dir $@)
	$(Q) sed -e "s/#/%/" < $^ > $@

clean-objs = $(stage3-objs) $(STAGE3) $(STAGE3).dis $(OUT)/x86_64/frame_nasm.h $(CLOSURE_TMPL)

clean: default-clean

.PHONY: all stage3 clean

include ../rules.mk
