all: image

force:

image: boot/boot 64/app
	cat boot/boot 64/app > image

boot/boot: force
	cd boot ; make

64/app: force
	cd 64 ; make 

musl:
	git clone git://git.musl-libc.org/musl
	cd musl ; git checkout v1.1.18

lwip-2.0.3:
	git clone http://git.savannah.nongnu.org/cgit/lwip.git 
	cd lwip ; git checkout -t STABLE-2_0_3_RELEASE

clean:
	cd boot ; make clean
	cd 64 ; make clean
	rm -f bootable

dist-clean: clean
	rm -rf musl lwip

run: image
	(sleep 2 ; echo "x") | qemu-system-x86_64 -device virtio-net -nographic  -drive file=image,format=raw
