VPATH += $(ROOT)/runtime $(ROOT)/runtime/heap

all:

$(ROOT)/runtime/contgen: contgen.c
	cc -std=c99 $< -g -o $(ROOT)/runtime/contgen

$(ROOT)/runtime/closure_templates.h: $(ROOT)/runtime/contgen
	$(ROOT)/runtime/contgen 10 10 > $(ROOT)/runtime/closure_templates.h


RUNTIME = table.o buffer.o format.o id.o symbol.o rolling.o freelist.o fragment.o sha256.o\
          timer.o pqueue.o tuple.o random.o signature.o rtrie.o tuple_parser.o runtime_init.o \
	  extra_prints.o debug_heap.o objcache.o merge.o

INCLUDES += -I$(ROOT)/runtime

CLEAN += $(ROOT)/runtime/contgen

