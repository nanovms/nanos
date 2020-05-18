SUBDIR=		contgen mkfs boot stage3 test

# runtime tests / ready-to-use targets
TARGET=		webg

ifneq ($(NANOS_TARGET_ROOT),)
TARGET_ROOT_OPT=	-r $(NANOS_TARGET_ROOT)
endif

MKFS=		$(OUTDIR)/mkfs/bin/mkfs
BOOTIMG=	$(OUTDIR)/boot/boot.img
STAGE3=		$(OUTDIR)/stage3/bin/stage3.img

IMAGE=		$(OUTDIR)/image/disk.raw
CLEANFILES+=	$(IMAGE)
CLEANDIRS+=	$(OUTDIR)/image

LWIPDIR=	$(VENDORDIR)/lwip
GITFLAGS+=	--depth 1  https://github.com/nanovms/lwip.git -b STABLE-2_1_2_RELEASE

# VMware
QEMU_IMG=	qemu-img

# GCE
GCLOUD= 	gcloud
GSUTIL=		gsutil
GCE_PROJECT=	prod-1033
GCE_BUCKET=	nanos-test/gce-images
GCE_IMAGE=	nanos-$(TARGET)
GCE_INSTANCE=	nanos-$(TARGET)

# AWS
AWS=		aws
JQ=		jq
PRINTF=		printf
CLEAR_LINE=	[1K\r
AWS_S3_BUCKET=	nanos-test
AWS_AMI_IMAGE=	nanos-$(TARGET)

all: image

include rules.mk

.PHONY: image release contgen mkfs boot stage3 target stage distclean

image: mkfs boot stage3 target
	@ echo "MKFS	$@"
	@ $(MKDIR) $(dir $(IMAGE))
	$(Q) $(MKFS) $(TARGET_ROOT_OPT) -b $(BOOTIMG) $(IMAGE) <test/runtime/$(TARGET).manifest

release: mkfs boot stage3
	$(Q) $(RM) -r release
	$(Q) $(MKDIR) release
	$(CP) $(MKFS) release
	$(CP) $(BOOTIMG) release
	$(CP) $(STAGE3) release
	cd release && $(TAR) -czvf nanos-release-$(REL_OS)-${version}.tar.gz *

contgen:
	$(Q) $(MAKE) -C $@

mkfs boot: contgen
	$(Q) $(MAKE) -C $@

stage3: $(LWIPDIR)/.vendored contgen
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

.PHONY: test-all test test-noaccel

test-all:
	$(Q) $(MAKE) -C test

test test-noaccel: mkfs boot stage3
	$(Q) $(MAKE) -C test test
	$(Q) $(MAKE) runtime-tests$(subst test,,$@)

RUNTIME_TESTS=	aio creat epoll eventfd fallocate fcntl fst getdents getrandom hw hws mkdir mmap pipe readv rename sendfile signal socketpair time unlink thread_test vsyscall write writev

.PHONY: runtime-tests runtime-tests-noaccel

runtime-tests runtime-tests-noaccel:
	$(foreach t,$(RUNTIME_TESTS),$(call execute_command,$(Q) $(MAKE) run$(subst runtime-tests,,$@) TARGET=$t))

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
QEMU_USERNET=	-device $(NETWORK)$(NETWORK_BUS),netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080,hostfwd=tcp::9090-:9090,hostfwd=udp::5309-:5309 -object filter-dump,id=filter0,netdev=n0,file=/tmp/nanos.pcap
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


##############################################################################
# VMware
CLEANFILES+=	$(IMAGE:.raw=.vmdk)

vmdk-image: image
	$(Q) $(QEMU_IMG) convert -f raw -O vmdk -o subformat=streamOptimized $(IMAGE) $(IMAGE:.raw=.vmdk)

##############################################################################
# GCE

.PHONY: upload-gce-image gce-image delete-gce-image
.PHONY: run-gce delete-gce gce-console

CLEANFILES+=	$(OUTDIR)/image/*-image.tar.gz

upload-gce-image: image
	$(Q) cd $(dir $(IMAGE)) && $(GNUTAR) cfz $(GCE_IMAGE)-image.tar.gz $(notdir $(IMAGE))
	$(Q) $(GSUTIL) cp $(dir $(IMAGE))$(GCE_IMAGE)-image.tar.gz gs://$(GCE_BUCKET)/$(GCE_IMAGE)-image.tar.gz

gce-image: upload-gce-image delete-gce-image
	$(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) images create $(GCE_IMAGE) --source-uri=https://storage.googleapis.com/$(GCE_BUCKET)/$(GCE_IMAGE)-image.tar.gz

delete-gce-image:
	- $(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) images delete $(GCE_IMAGE) --quiet

run-gce: delete-gce
	$(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) instances create $(GCE_INSTANCE) --machine-type=custom-1-2048 --image=$(GCE_IMAGE) --image-project=$(GCE_PROJECT) --tags=nanos
	$(Q) $(MAKE) gce-console

delete-gce:
	- $(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) instances delete $(GCE_INSTANCE) --quiet

gce-console:
	$(Q) $(GCLOUD) compute --project=$(GCE_PROJECT) instances tail-serial-port-output $(GCE_INSTANCE)

##############################################################################
# AWS
.PHONY: upload-ec2-image create-ec2-snapshot

upload-ec2-image:
	$(Q) $(AWS) s3 cp $(IMAGE) s3://$(AWS_S3_BUCKET)/$(AWS_AMI_IMAGE).raw

create-ec2-snapshot: upload-ec2-image
	$(Q) json=`$(AWS) ec2 import-snapshot --disk-container "Description=NanoVMs Test,Format=raw,UserBucket={S3Bucket=$(AWS_S3_BUCKET),S3Key=$(AWS_AMI_IMAGE).raw}"` && \
		import_task_id=`$(ECHO) "$$json" | $(JQ) -r .ImportTaskId` && \
		while :; do \
			json=`$(AWS) ec2 describe-import-snapshot-tasks --import-task-ids $$import_task_id`; \
			status=`$(ECHO) "$$json" | $(JQ) -r ".ImportSnapshotTasks[0].SnapshotTaskDetail.Status"`; \
			if [ x"$$status" = x"completed" ]; then \
			        $(PRINTF) "$(CLEAR_LINE)Task $$import_task_id: $$status\n"; \
				break; \
			fi; \
			progress=`$(ECHO) "$$json" | $(JQ) -r ".ImportSnapshotTasks[0].SnapshotTaskDetail.Progress?"`; \
			status_message=`$(ECHO) "$$json" | $(JQ) -r ".ImportSnapshotTasks[0].SnapshotTaskDetail.StatusMessage?"`; \
			$(PRINTF) "$(CLEAR_LINE)Task $$import_task_id: $$status_message ($$progress%%)"; \
		done

ifeq ($(UNAME_s),Darwin)
REL_OS=		darwin
QEMU_ACCEL=	-accel $(ACCEL) -cpu host
ACCEL?=		hvf
# ACCEL=?	hax
else
REL_OS=		linux
QEMU_ACCEL=	-enable-kvm -cpu host
endif
