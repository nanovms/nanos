all: boot

STAGE2SIZE = 2048

b32.pad: b32
	dd if=$< of=$@ bs=$(STAGE2SIZE) conv=sync

stage1: stage1.s
	nasm $< -o $@

boot: stage1 b32.pad
	cat stage1 b32.pad > boot
	
OBJ = serial.o bottom.o runtime.o stage2.o 

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
	cc -m32 -I. -I../runtime $< -c

clean:
	rm -f *.o *~ b32.elf b32 bottom.list stage1


