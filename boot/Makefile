all: boot

STAGE2SIZE = 4096
STAGE3SIZE = 124016

b32.pad: b32
	dd if=$< of=$@ bs=$(STAGE2SIZE) conv=sync

stage1: stage1.s
	nasm -l boxxy -dSTAGE3SIZE=$(STAGE3SIZE) -dSTAGE2SIZE=$(STAGE2SIZE) $< -o $@

boot: stage1 b32.pad
	cat stage1 b32.pad > boot

OBJ = bottom.o stage2.o 

VPATH = ../runtime
LD = ld
OD = objdump

b32.elf: $(OBJ) linker_script
	$(LD) -T linker_script -e _start $(OBJ) $(LIBC) -o $@

b32: b32.elf
	 objcopy -S -O binary $< $@

bottom.o: bottom.s
	nasm -felf $<

%.o: %.c
	cc -m32 -DSTAGE3SIZE=$(STAGE3SIZE) -DSTAGE2SIZE=$(STAGE2SIZE) -I. -I../runtime $< -c

clean:
	rm -f *.o *~ b32.elf b32 bottom.list stage1 boxxy b32.pad boot


