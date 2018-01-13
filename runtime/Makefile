VPATH += $(ROOT)/runtime

crt0.o: crt0.s
	nasm -felf64 $< -o $@

RUNTIME = crt0.o lib.o serial.o pci.o service.o musl_shims.o interrupt.o page.o


INCLUDES += -I$(ROOT)/runtime

