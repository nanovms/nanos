all: image

force:

image: boot/boot example/app
	cat boot/boot example/app > image

boot/boot: force
	cd boot ; make

example/app: force
	cd example ; make 

musl:
	git clone git://git.musl-libc.org/musl
	cd musl ; git checkout v1.1.18

lwip:
	git clone http://git.savannah.nongnu.org/git/lwip.git 
	cd lwip ; git checkout -t STABLE-2_0_3_RELEASE

clean:
	cd boot ; make clean
	cd example ; make clean
	rm -f bootable

dist-clean: clean
	rm -rf musl lwip

run: image
	(sleep 2 ; echo "x") | qemu-system-x86_64 -device virtio-net -nographic  -drive file=image,format=raw
