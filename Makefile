include config.mk

all: image test

image: mkfs boot stage3 target
	@ echo "MKFS	$@"
	@ mkdir -p $(dir $(IMAGE))
	$(Q) $(MKFS) $(FS) < examples/$(TARGET).manifest && cat $(BOOTIMG) $(FS) > $(IMAGE)

stage: image
	- mkdir -p .staging
	- cp -a output/mkfs/bin/mkfs .staging/mkfs
	- cp -a output/boot/boot.img .staging/boot.img
	- cp -a output/stage3/stage3.img .staging/stage3.img

contgen: $(CONTGEN)

mkfs: mkfs-build

boot: boot-build

stage3: stage3-build

test: test-build

examples: examples-build

target: $(TARGET)

$(TARGET): contgen
	$(MAKE) -C examples

unit-test: test
	$(MAKE) -C test unit-test

runtests: image
	$(MAKE) -C tests deps
	$(MAKE) -C tests test

%-build: contgen
	$(MAKE) -C $(subst -build,,$@)

%-clean:
	$(MAKE) -C $(subst -clean,,$@) clean

clean:
	$(MAKE) $(addsuffix -clean,contgen boot stage3 mkfs examples test)
	$(MAKE) -C tests clean
	$(Q) $(RM) -fd $(dir $(IMAGE)) output

distclean: clean
	$(Q) $(RM) -rf $(VENDOR)

DEBUG	?= n
DEBUG_	:=
ifeq ($(DEBUG),y)
	DEBUG_ := -s
endif

STORAGE	= -drive file=$(IMAGE),format=raw,if=virtio
TAP	= -netdev tap,id=n0,ifname=tap0,script=no,downscript=no
NET	= -device virtio-net,mac=7e:b8:7e:87:4a:ea,netdev=n0 $(TAP)
KVM	= -enable-kvm
DISPLAY	= -display none -serial stdio
USERNET	= -device virtio-net,netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=tcp::9090-:9090,hostfwd=udp::5309-:5309
QEMU	?= qemu-system-x86_64

run-nokvm: image
	- $(QEMU) $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(USERNET) $(DEBUG_)

run: image
	- $(QEMU) $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(NET) $(KVM) $(DEBUG_)

runnew: image
	- ~/qemu/x86_64-softmmu/qemu-system-x86_64 -hda image $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(USERNET) $(KVM)

.PHONY: image contgen mkfs boot stage3 examples gotest test clean distclean run-nokvm run runnew

include rules.mk
