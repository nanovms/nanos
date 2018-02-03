VPATH += $(ROOT)/runtime

crt0.o: crt0.s
	nasm -felf64 $< -o $@


$(ROOT)/runtime/contgen: contgen.c
	cc -std=c99 $< -g -o $(ROOT)/runtime/contgen

$(ROOT)/runtime/continuation_templates.h: contgen
	$(ROOT)/runtime/contgen 10 10 > $(ROOT)/runtime/continuation_templates.h


#format.o
RUNTIME = $(ROOT)/runtime/continuation_templates.h table.o buffer.o format.o storage.o
STANDALONE = $(RUNTIME) service.o interrupt.o page.o serial.o crt0.o pci.o elf.o system.o
UNIXRUNTIME = $(RUNTIME) unix_context.o

INCLUDES += -I$(ROOT)/runtime

