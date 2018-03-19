VPATH += $(ROOT)/x86_64


crt0.o: crt0.s
	nasm -felf64 $< -o $@

INCLUDES += -I$(ROOT)/x86_64
X86_64_OBJ= pci.o serial.o page.o interrupt.o clock.o crt0.o service.o elf.o
# break this out at some point 
SYSCALL_INTERFACE = unix.o
GDBSTUB = gdbstub.o gdbutil.o breakpoint.o
