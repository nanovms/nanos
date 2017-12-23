all: b32

OBJ = serial.o bottom.o runtime.o stage2.o pages.o

VPATH = ../runtime
LD = ld
OD = objdump

b32.elf: $(OBJ) linker_script
	$(LD) -T linker_script -e _start $(OBJ) $(LIBC) -o $@

b32: b32.elf
	 objcopy -S -O binary $< $@

bottom.o: bottom.s
	nasm -l bottom.list -felf $<

%.o: %.c
	cc -m32 -I. -I../runtime $< -c

clean:
	rm -f *.o *~ b32.elf b32 bottom.list


