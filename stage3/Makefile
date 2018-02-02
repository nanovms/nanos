all: image

ROOT = ..
force:
include $(ROOT)/runtime/Makefile
include $(ROOT)/virtio/Makefile
INCLUDES += -I.

LDSO =/home/yuri/gb/elf/ld.so
#LDSO =  /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
PROGRAM =/usr/bin/mono

image: $(ROOT)/boot/boot stage3
	cat $(ROOT)/boot/boot stage3 > image

#seems like it would be easier to just use nasm to get these into aligned sections
#or...move these into the filesystem by alignment

LDNAME = $(subst -,_,$(subst .,_,$(subst /,_,$(LDSO))))
PROGRAMNAME = $(subst -,_,$(subst .,_,$(subst /,_,$(PROGRAM))))

ldso.o: $(LDSO)
	objcopy -I binary -O elf64-x86-64 -B i386:x86-64 --redefine-sym _binary_$(LDNAME)_end=_ldso_end --redefine-sym _binary_$(LDNAME)_start=_ldso_start $< $@
	objcopy --rename-section .data=.ldso ldso.o ldso.o

program.o: $(PROGRAM)
	objcopy -I binary -O elf64-x86-64 -B i386:x86-64 --redefine-sym _binary_$(PROGRAMNAME)_end=_program_end --redefine-sym _binary_$(PROGRAMNAME)_start=_program_start $< $@
	objcopy --rename-section .data=.program program.o program.o

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

stage3: ldso.o program.o fs.o stage3.o system.o $(STANDALONE) 
	ld -e_start -T linker_script -nostdlib $^ -o stage3

.c.o:
	cc $(INCLUDES) -nostdinc -fno-stack-protector $< -c

clean:
	cd $(ROOT)/boot ; make clean
	rm -f image *.o fs

distclean: clean
	rm -rf lwip libc/musl

run: image
	(sleep 8 ; echo "x") | qemu-system-x86_64 -d int -D foo  -nographic -drive file=image,format=raw

