all: image test

force:

ROOT = .

image: net/lwip force 
	make -f image.mk image

net/lwip:
	(cd $(ROOT)/net; git clone http://git.savannah.nongnu.org/git/lwip.git ; cd lwip ; git checkout STABLE-2_0_3_RELEASE)

test: force
	cd test ; make

unit-test: test
	cd test ; make unit-test

distclean: clean
	rm -rf net/lwip

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	cd test ; make clean
	cd examples ; make clean
	rm -f runtime/closure_templates.h runtime/contgen image fs

DEBUG ?= n
ifeq ($(DEBUG),y)
	DEBUG_ := -s
else
	DEBUG_ :=
endif

# file=image,if=none,id=virtio-disk0,format=raw,cache=none,aio=native

# could really be nice if BOOT and STORAGE could be the same disk
BOOT = -boot c -drive file=image,format=raw,if=ide
STORAGE = -drive file=image,format=raw,if=virtio
TAP = -netdev tap,id=n0,ifname=tap0,script=no,downscript=no
NET = -device virtio-net,mac=7e:b8:7e:87:4a:ea,netdev=n0 $(TAP)
KVM = -enable-kvm
DISPLAY = -display none -serial stdio
USERNET = -device virtio-net,netdev=n0 -netdev user,id=n0,hostfwd=tcp::8080-:8080
QEMU ?= qemu-system-x86_64

run-nokvm: image
	- $(QEMU) $(BOOT) $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(USERNET) $(DEBUG_)

run: image
	- $(QEMU) $(BOOT) $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(NET) $(KVM) $(DEBUG_)

runnew: image
	- ~/qemu/x86_64-softmmu/qemu-system-x86_64 -hda image $(DISPLAY) -m 2G -device isa-debug-exit -no-reboot $(STORAGE) $(USERNET) $(KVM)


