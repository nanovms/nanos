all: boot

ROOT ?= $(PWD)/..
include $(ROOT)/x86_64/Makefile
include $(ROOT)/runtime/Makefile
include $(ROOT)/tfs/Makefile


STAGE1SIZE = 512
# make can figure this out if we just spend enough time convincing it to
STAGE2SIZE = 8192

stage2.pad: stage2
	dd if=$< of=$@ bs=$(STAGE2SIZE) conv=sync

stage2.strip: stage2.elf
	strip stage2.elf -o stage2.strip

stage1: stage1.s
	nasm  -dSTAGE1SIZE=$(STAGE3SIZE) -dSTAGE2SIZE=$(STAGE2SIZE) $< -o $@

boot: stage1 stage2.pad
	cat stage1 stage2.pad > boot

OBJ = service32.o stage2.o serial.o page.o elf.o zero_wrap.o kvm_platform.o tfs.o vector.o tlog.o table.o

LD = ld
OD = objdump

stage2.elf: $(OBJ) linker_script
	$(LD) -T linker_script -e _start $(OBJ) $(LIBC) -o $@

stage2: stage2.strip
	 objcopy -S -O binary $< $@

service32.o: service32.s
	nasm -felf $<

%.o: %.c $(ROOT)/runtime/closure_templates.h
	cc -m32 -O -fno-stack-protector -include def32.h $(INCLUDES) -DSTAGE1SIZE=$(STAGE1SIZE) -DSTAGE2SIZE=$(STAGE2SIZE) -I. -I../runtime $< -c

clean:
	rm -f *.o *~ stage2.elf stage2 bottom.list stage1 boxxy stage2.pad boot


