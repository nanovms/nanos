VPATH += $(ROOT)/runtime

crt0.o: crt0.s
	nasm -felf64 $< -o $@

#format.o
RUNTIME =   table.o buffer.o format.o
STANDALONE = $(RUNTIME) service.o interrupt.o page.o serial.o crt0.o pci.o 

INCLUDES += -I$(ROOT)/runtime

