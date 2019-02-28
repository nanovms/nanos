include config.mk

all: image test

image: gitversion.c mkfs boot stage3 target
	@ echo "MKFS	$@"
	@ mkdir -p $(dir $(IMAGE))
	$(Q) $(MKFS) $(TARGET_ROOT_OPT) $(FS) < examples/$(TARGET).manifest && cat $(BOOTIMG) $(FS) > $(IMAGE)

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

gitversion.c : .git/index .git/HEAD
	echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > $@

unit-test: test
	$(MAKE) -C test unit-test

gcov: test
	$(MAKE) -C test gcov

runtests: image
	$(MAKE) -C tests deps
	$(MAKE) -C tests test

%-runtest:
	$(MAKE) TARGET=$(subst -runtest,,$@) run-nokvm

runtime-tests:
	$(MAKE) -j1 $(addsuffix -runtest,creat fst getdents getrandom hw hws mkdir pipe write)

%-build: contgen
	$(MAKE) -C $(subst -build,,$@)

%-clean:
	$(MAKE) -C $(subst -clean,,$@) clean

clean:
	$(MAKE) $(addsuffix -clean,contgen boot stage3 mkfs examples test)
	$(MAKE) -C tests clean
	$(Q) $(RM) -f $(FS) $(IMAGE)
	$(Q) $(RM) -rfd $(dir $(IMAGE)) output
	$(Q) $(RM) -f gitversion.c

distclean: clean
	$(Q) $(RM) -rf $(VENDOR)

DEBUG	?= n
DEBUG_	:=
ifeq ($(DEBUG),y)
	DEBUG_ := -s
endif

ifneq ($(NANOS_TARGET_ROOT),)
TARGET_ROOT_OPT= -r $(NANOS_TARGET_ROOT)
endif

STORAGE	= -drive if=none,id=hd0,format=raw,file=$(IMAGE)
STORAGE+= -device virtio-blk,drive=hd0
#STORAGE+= -device virtio-scsi-pci,id=scsi0 -device scsi-hd,bus=scsi0.0,drive=hd0
TAP	= -netdev tap,id=n0,ifname=tap0,script=no,downscript=no
NET	= -device virtio-net,mac=7e:b8:7e:87:4a:ea,netdev=n0 $(TAP)
KVM	= -enable-kvm
DISPLAY	= -display none -serial stdio
USERNET	= -device virtio-net,netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=tcp::9090-:9090,hostfwd=udp::5309-:5309
QEMU	?= qemu-system-x86_64

run-nokvm: image
	$(QEMU) $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(USERNET) $(DEBUG_) || exit $$(($$?>>1))

run: image
	$(QEMU) $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(NET) $(KVM) $(DEBUG_) || exit $$(($$?>>1))

.PHONY: image contgen mkfs boot stage3 examples gotest test clean distclean run-nokvm run runnew

include rules.mk
