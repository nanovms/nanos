all: image

force:

ROOT = .

image: net/lwip force 
	make -f image.mk image

net/lwip:
	(cd $(ROOT)/net; git clone http://git.savannah.nongnu.org/git/lwip.git ; cd lwip ; git checkout STABLE-2_0_3_RELEASE)

distclean: clean
	rm -rf net/lwip

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	cd examples ; make clean
	rm -f runtime/closure_templates.h runtime/contgen image image2

# need to get boot and virtio storage to use the same file without
# contending on the write lock - cant set read only

image2: image
	cp image image2

# file=image,if=none,id=virtio-disk0,format=raw,cache=none,aio=native

# could really be nice if BOOT and STORAGE could be the same disk
BOOT = -boot c -drive file=image,format=raw,if=ide
STORAGE = -drive file=image2,format=raw,if=virtio
TAP = -netdev tap,id=n0,ifname=tap0
NET = -device virtio-net,mac=7e:b8:7e:87:4a:ea,netdev=n0 $(TAP)
KVM = -enable-kvm

run-nokvm: image image2
	- qemu-system-x86_64 $(BOOT) -nographic -m 2G -device isa-debug-exit $(STORAGE) 

run: image image2
	- qemu-system-x86_64 $(BOOT) -nographic -m 2G -device isa-debug-exit $(STORAGE) $(NET) $(KVM)

runnew: image image2
	- ~/qemu/x86_64-softmmu/qemu-system-x86_64 -hda image -nographic -m 2G -device isa-debug-exit $(STORAGE) $(NET) $(KVM)

