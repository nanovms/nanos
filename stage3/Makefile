all: image

ROOT = ..
force:
include $(ROOT)/runtime/Makefile
include $(ROOT)/virtio/Makefile

image: $(ROOT)/boot/boot stage3
	cat $(ROOT)/boot/boot stage3 > image

%.o: %.bin
	objcopy -I binary -O elf64-x86-64 -B i386:x86-64 $< $@

$(ROOT)/boot/boot: force
	cd $(ROOT)/boot ; make


stage3: test.o stage3.o $(RUNTIME) 
	ld -e_start -T linker_script -nostdlib $^ -o stage3

.c.o:
	cc $(INCLUDES) -nostdinc -fno-stack-protector $< -c

clean:
	cd $(ROOT)/boot ; make clean
	rm -f image *.o

distclean: clean
	rm -rf lwip libc/musl

run: image
	(sleep 4 ; echo "x") | qemu-system-x86_64 -d int -D foo  -nographic -drive file=image,format=raw

