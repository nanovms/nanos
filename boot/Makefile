all: boot

STAGE1SIZE = 512
STAGE2SIZE = 12288

stage2.pad: stage2
	dd if=$< of=$@ bs=$(STAGE2SIZE) conv=sync

stage1: stage1.s
	nasm  -dSTAGE1SIZE=$(STAGE3SIZE) -dSTAGE2SIZE=$(STAGE2SIZE) $< -o $@

boot: stage1 stage2.pad
	cat stage1 stage2.pad > boot

OBJ = service32.o stage2.o serial.o page.o elf.o

VPATH = ../runtime
LD = ld
OD = objdump

stage2.elf: $(OBJ) linker_script
	$(LD) -T linker_script -e _start $(OBJ) $(LIBC) -o $@

stage2: stage2.elf
	 objcopy -S -O binary $< $@

service32.o: service32.s
	nasm -felf $<

%.o: %.c
	cc -m32 -fno-stack-protector -include def32.h -DSTAGE1SIZE=$(STAGE1SIZE) -DSTAGE2SIZE=$(STAGE2SIZE) -I. -I../runtime $< -c

clean:
	rm -f *.o *~ stage2.elf stage2 bottom.list stage1 boxxy stage2.pad boot


