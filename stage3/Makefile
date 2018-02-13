all: image

ROOT = ..
force:
include $(ROOT)/runtime/Makefile
include $(ROOT)/virtio/Makefile
INCLUDES += -I.

image: $(ROOT)/boot/boot stage3
	cat $(ROOT)/boot/boot stage3 > image

FSNAME = fs
fs.o: fs
	objcopy -I binary -O elf64-x86-64 -B i386:x86-64 --redefine-sym _binary_$(FSNAME)_end=_fs_end --redefine-sym _binary_$(FSNAME)_start=_fs_start $< $@
	objcopy --rename-section .data=.fs fs.o fs.o

$(ROOT)/boot/boot: force
	cd $(ROOT)/boot ; make

$(ROOT)/mkfs/mkfs: force
	cd $(ROOT)/mkfs ; make

fs: $(ROOT)/mkfs/mkfs filesystem
	$(ROOT)/mkfs/mkfs < filesystem > fs

stage3: fs.o stage3.o $(STANDALONE) 
	ld -e_start -T linker_script -nostdlib $^ -o stage3

.c.o:
	cc $(INCLUDES) -nostdinc -fno-stack-protector $< -c

clean:
	cd $(ROOT)/boot ; make clean
	rm -f image *.o fs

run: image
	- qemu-system-x86_64 -d int -D foo  -nographic -drive file=image,format=raw -m 2G -device isa-debug-exit

