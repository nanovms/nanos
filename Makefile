all: image

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
STORAGE =  -device virtio-blk-pci,scsi=off,file=image
NET =  -device virtio-net,netdev=n0,mac=4a:a4:e1:21:01:9c -netdev tap,id=n0,ifname=tap0

run: image
	- qemu-system-x86_64  -nographic -drive file=image,format=raw -m 2G -device isa-debug-exit 

