ROOT = $(PWD)

include net/Makefile

force:

mkfs/mkfs:
	cd mkfs ; make


image: boot/boot mkfs/mkfs manifest stage3/stage3 examples/web
	mkfs/mkfs < manifest | cat boot/boot - > image

examples/web: force
	cd examples ; make

boot/boot: force
	cd boot ; make

stage3/stage3: force
	cd stage3 ; make

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	rm -f runtime/closure_templates.h runtime/contgen image image2
