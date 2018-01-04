all: image

force:

image: boot/boot example/app
	cat boot/boot example/app > image

boot/boot: force
	cd boot ; make

example/app: lwip force
	cd example ; make 

lwip:
	git clone http://git.savannah.nongnu.org/git/lwip.git 
	cd lwip ; git checkout STABLE-2_0_3_RELEASE

clean:
	cd boot ; make clean
	cd example ; make clean
	cd libc ; make clean
	rm -f bootable

distclean: clean
	rm -rf lwip libc/musl

run: image
	(sleep 4 ; echo "x") | qemu-system-x86_64 -device virtio-net,netdev=n0,mac=4a:a4:e1:21:01:9c -netdev tap,id=n0,ifname=tap0,script=no -nographic  -drive file=image,format=raw

