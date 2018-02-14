all: image

mkfs/mkfs:
	cd mkfs ; make

image: boot/boot mkfs/mkfs manifest stage3/stage3 
	mkfs/mkfs < manifest | cat boot/boot - > image

boot/boot:
	cd boot ; make

stage3/stage3:
	cd stage3 ; make

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	rm -f runtime/closure_templates.h runtime/contgen image

STORAGE = -drive file=/dev/sda8,if=none,id=virtio-disk0,format=raw,cache=none,aio=native -device virtio-blk-pci,scsi=off,drive=virtio-disk0,id=disk0
NET =  -device virtio-net,netdev=n0,mac=4a:a4:e1:21:01:9c -netdev tap,id=n0,ifname=tap0

run: stage3/image
	- qemu-system-x86_64  -nographic -drive file=stage3/image,format=raw -m 2G -device isa-debug-exit

