
all:mkfs

ROOT=$(PWD)/..

include $(ROOT)/runtime/Makefile

%.o: %.c $(ROOT)/runtime/closure_templates.h
	cc -g -c $(INCLUDES) $<

mkfs: main.o $(UNIXRUNTIME)
	cc $^ -g -o mkfs

dump: dump.o $(UNIXRUNTIME)
	cc $^ -g -o mkfs

clean:
	rm -f *.o mkfs

