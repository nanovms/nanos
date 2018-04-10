VPATH += $(ROOT)/runtime $(ROOT)/runtime/heap

all:

$(ROOT)/runtime/contgen: contgen.c
	cc -std=c99 $< -g -o $(ROOT)/runtime/contgen

$(ROOT)/runtime/closure_templates.h: $(ROOT)/runtime/contgen
	$(ROOT)/runtime/contgen 10 10 > $(ROOT)/runtime/closure_templates.h


RUNTIME = table.o buffer.o format.o id.o symbol.o rolling.o freelist.o
UNIXRUNTIME = $(RUNTIME) unix_context.o

INCLUDES += -I$(ROOT)/runtime

CLEAN += $(ROOT)/runtime/contgen

