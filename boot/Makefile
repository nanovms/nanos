# using  > 4.0 guile support..who knew that guile was still a thing
all: boot

ROOT ?= $(PWD)/..
include $(ROOT)/x86_64/Makefile
include $(ROOT)/runtime/Makefile
include $(ROOT)/tfs/Makefile

CC = cc

STAGE1SIZE = 512

stage2.pad: stage2
	dd if=$< of=$@ bs=512 conv=sync

stage2.strip: stage2.elf
	strip stage2.elf -o stage2.strip

stage1: stage1.s stage2.pad
	nasm  -l stage1.lst -dSTAGE1SIZE=$(STAGE1SIZE) -dSTAGE2SIZE=$(shell stat -c %s stage2.pad) $< -o $@

boot: stage1 stage2.pad
	cat stage1 stage2.pad > boot

# move out to runtime
SRUNTIME = table.o buffer.o format.o id.o symbol.o rolling.o tuple.o random.o rtrie.o runtime_init.o extra_prints.o debug_heap.o
OBJ = service32.o stage2.o serial.o page.o elf.o zero_wrap.o kvm_platform.o merge.o $(TFS) $(SRUNTIME)

LD = ld
OD = objdump

stage2.elf: $(OBJ) linker_script
	$(LD) -T linker_script -e _start $(OBJ) $(LIBC) -o $@

stage2: stage2.strip
	 objcopy -S -O binary $< $@

service32.o: service32.s
	nasm -felf $<

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) -m32 -O -fno-stack-protector -include def32.h $(INCLUDES) -I. -I../runtime $< -c

clean:
	rm -f *.o *~ stage2.elf stage2 bottom.list stage1 stage2.pad boot


