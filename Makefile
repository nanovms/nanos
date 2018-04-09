all: image

ROOT = $(PWD)

include net/Makefile

force:

mkfs/mkfs:
	cd mkfs ; make


net/lwip:
	git clone http://git.savannah.nongnu.org/git/lwip.git 
	cd lwip ; git checkout STABLE-2_0_3_RELEASE

image: boot/boot mkfs/mkfs manifest stage3/stage3 hw/hw
	mkfs/mkfs < manifest | cat boot/boot - > image

hw/hw: force
	cd hw  ; make

boot/boot: force
	cd boot ; make

stage3/stage3: force
	cd stage3 ; make

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	rm -f runtime/closure_templates.h runtime/contgen image image2

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

