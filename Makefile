all: image

ROOT = $(PWD)

include net/Makefile

force:

mkfs/mkfs:
	cd mkfs ; make

image: boot/boot mkfs/mkfs manifest stage3/stage3 
	mkfs/mkfs < manifest | cat boot/boot - > image

boot/boot: force
	cd boot ; make

stage3/stage3: force
	cd stage3 ; make

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	rm -f runtime/closure_templates.h runtime/contgen image

# file=image,if=none,id=virtio-disk0,format=raw,cache=none,aio=native

STORAGE =  -device virtio-blk-pci,scsi=off,drive=foo -drive file=image,format=raw,id=foo,if=none
NET =  -device virtio-net,mac=62:5e:e0:2b:2e:4d # netdev=n0,
TAP = -netdev tap,id=n0,ifname=tap0
run: image
	- qemu-system-x86_64  -hda image -nographic -m 2G -device isa-debug-exit $(STORAGE) $(NET)

