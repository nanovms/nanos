VPATH += $(ROOT)/runtime $(ROOT)/runtime/heap

all:

crt0.o: crt0.s
	nasm -felf64 $< -o $@


$(ROOT)/runtime/contgen: contgen.c
	cc -std=c99 $< -g -o $(ROOT)/runtime/contgen

$(ROOT)/runtime/closure_templates.h: $(ROOT)/runtime/contgen
	$(ROOT)/runtime/contgen 10 10 > $(ROOT)/runtime/closure_templates.h


RUNTIME = table.o buffer.o format.o storage.o id.o
system.o: $(ROOT)/runtime/closure_templates.h
STANDALONE = $(RUNTIME) service.o interrupt.o page.o serial.o crt0.o pci.o elf.o system.o
UNIXRUNTIME = $(RUNTIME) unix_context.o

INCLUDES += -I$(ROOT)/runtime

CLEAN += $(ROOT)/runtime/contgen

