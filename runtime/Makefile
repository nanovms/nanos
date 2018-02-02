VPATH += $(ROOT)/runtime

crt0.o: crt0.s
	nasm -felf64 $< -o $@

#format.o
RUNTIME = table.o buffer.o format.o storage.o
STANDALONE = $(RUNTIME) service.o interrupt.o page.o serial.o crt0.o pci.o elf.o system.o
UNIXRUNTIME = $(RUNTIME) unix_context.o

INCLUDES += -I$(ROOT)/runtime

