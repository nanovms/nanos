all: image

clean:
	make -f image.mk clean

distclean: clean
	rm -rf net/lwip

image: net/lwip
	make -f image.mk image

ROOT = .
net/lwip:
	(cd $(ROOT)/net; git clone http://git.savannah.nongnu.org/git/lwip.git ; cd lwip ; git checkout STABLE-2_0_3_RELEASE)

# need to get boot and virtio storage to use the same file without
# contending on the write lock - cant set read only

image2: image
	cp image image2

# file=image,if=none,id=virtio-disk0,format=raw,cache=none,aio=native

STORAGE =  -device virtio-blk-pci,scsi=off,drive=foo -drive file=image2,format=raw,id=foo,if=none
TAP = -netdev tap,id=n0,ifname=tap0
NET = -device virtio-net,mac=7e:b8:7e:87:4a:ea,netdev=n0 $(TAP)
KVM = -enable-kvm
run: image image2
	- qemu-system-x86_64 -hda image -nographic -m 2G -device isa-debug-exit $(STORAGE) $(NET) $(KVM)

