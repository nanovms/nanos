SUBDIR=		contgen mkfs boot stage3 test

# runtime tests / ready-to-use targets
TARGET=		webg

ifneq ($(NANOS_TARGET_ROOT),)
TARGET_ROOT_OPT=	-r $(NANOS_TARGET_ROOT)
endif

MKFS=		$(OUTDIR)/mkfs/bin/mkfs
BOOTIMG=	$(OUTDIR)/boot/boot.img
STAGE3=		$(OUTDIR)/stage3/bin/stage3.img

IMAGE=		$(OUTDIR)/image/image
FS=		$(OUTDIR)/image/fs
CLEANFILES+=	$(IMAGE) $(FS)
CLEANDIRS+=	$(OUTDIR)/image

# GCE
GCLOUD= 	gcloud
GSUTIL=		gsutil
GCE_PROJECT=	prod-1033
GCE_BUCKET=	nanos-test/gce-images
GCE_IMAGE=	nanos-$(TARGET)
GCE_INSTANCE=	nanos-$(TARGET)

all: image

.PHONY: image release contgen mkfs boot stage3 target stage distclean

image: mkfs boot stage3 target
	@ echo "MKFS	$@"
	@ $(MKDIR) $(dir $(IMAGE))
	$(Q) $(MKFS) $(TARGET_ROOT_OPT) $(FS) <test/runtime/$(TARGET).manifest && cat $(BOOTIMG) $(FS) >$(IMAGE)

release: mkfs boot stage3
	$(Q) $(RM) -r release
	$(Q) $(MKDIR) release
	$(CP) $(MKFS) release
	$(CP) $(BOOTIMG) release
	$(CP) $(STAGE3) release
	cd release && $(TAR) -czvf nanos-release-$(REL_OS)-${version}.tar.gz *

contgen:
	$(Q) $(MAKE) -C $@

mkfs boot stage3: contgen
	$(Q) $(MAKE) -C $@

target: contgen
	$(Q) $(MAKE) -C test/runtime $(TARGET)

stage: mkfs boot stage3
	$(Q) $(MKDIR) .staging
	$(Q) $(CP) -a $(MKFS) .staging/mkfs
	$(Q) $(CP) -a $(BOOTIMG) .staging/boot.img
	$(Q) $(CP) -a $(STAGE3) .staging/stage3.img

distclean: clean
	$(Q) $(RM) -rf $(VENDORDIR)

##############################################################################
# tests

.PHONY: test test-nokvm

test test-nokvm: mkfs boot stage3
	$(Q) $(MAKE) -C test all test # explictly build all tests to check all is buildable
	$(Q) $(MAKE) runtime-tests$(subst test,,$@)

RUNTIME_TESTS=	creat fst getdents getrandom hw hws mkdir pipe write

.PHONY: runtime-tests runtime-tests-nokvm

runtime-tests runtime-tests-nokvm:
	$(foreach t,$(RUNTIME_TESTS),$(call execute_command,$(Q) $(MAKE) run$(subst runtime-tests,,$@) TARGET=$t))

##############################################################################
# run

.PHONY: run run-bridge run-nokvm

QEMU=		qemu-system-x86_64

QEMU_MEMORY=	-m 2G
QEMU_DISPLAY=	-display none -serial stdio
QEMU_STORAGE=	-drive if=none,id=hd0,format=raw,file=$(IMAGE)
#QEMU_STORAGE+= -device virtio-blk,drive=hd0
QEMU_STORAGE+=	-device virtio-scsi-pci,id=scsi0 -device scsi-hd,bus=scsi0.0,drive=hd0
QEMU_TAP=	-netdev tap,id=n0,ifname=tap0,script=no,downscript=no
QEMU_NET=	-device virtio-net,mac=7e:b8:7e:87:4a:ea,netdev=n0 $(QEMU_TAP)
QEMU_USERNET=	-device virtio-net,netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=tcp::9090-:9090,hostfwd=udp::5309-:5309
QEMU_KVM=	-enable-kvm
QEMU_FLAGS=

QEMU_COMMON=	$(QEMU_DISPLAY) $(QEMU_MEMORY) $(QEMU_STORAGE) -device isa-debug-exit -no-reboot $(QEMU_FLAGS)

run: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) $(QEMU_KVM) || exit $$(($$?>>1))

run-bridge: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) $(QEMU_KVM) || exit $$(($$?>>1))

run-nokvm: image
	$(QEMU) $(QEMU_COMMON) $(QEMU_USERNET) || exit $$(($$?>>1))

##############################################################################
# GCE

.PHONY: upload-gce-image gce-image delete-gce-image
.PHONY: run-gce delete-gce gce-console

CLEANFILES+=	$(OUTDIR)/image/disk.raw $(OUTDIR)/image/*-image.tar.gz

upload-gce-image: image
	$(Q) $(LN) -f $(IMAGE) $(dir $(IMAGE))disk.raw
	$(Q) cd $(dir $(IMAGE)) && $(GNUTAR) cfz $(GCE_IMAGE)-image.tar.gz disk.raw
	$(Q) $(GSUTIL) cp $(dir $(IMAGE))$(GCE_IMAGE)-image.tar.gz gs://$(GCE_BUCKET)/$(GCE_IMAGE)-image.tar.gz

gce-image: upload-gce-image delete-gce-image
	$(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) images create $(GCE_IMAGE) --source-uri=https://storage.googleapis.com/$(GCE_BUCKET)/$(GCE_IMAGE)-image.tar.gz

delete-gce-image:
	- $(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) images delete $(GCE_IMAGE) --quiet

run-gce: delete-gce
	$(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) instances create $(GCE_INSTANCE) --machine-type=custom-1-2048 --image=nanos-$(TARGET) --image-project=$(GCE_PROJECT) --tags=nanos
	$(Q) $(MAKE) gce-console

delete-gce:
	- $(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) instances delete $(GCE_INSTANCE) --quiet

gce-console:
	$(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) instances tail-serial-port-output $(GCE_INSTANCE)

include rules.mk

ifeq ($(UNAME_s),Linux)
REL_OS=	linux
endif

ifeq ($(UNAME_s),Darwin)
REL_OS=	darwin
endif
