
all:mkfs

ROOT=$(PWD)/..

INCLUDES = -include def64.h
include $(ROOT)/runtime/Makefile
INCLUDES += -I$(ROOT)/x86_64

%.o: %.c $(ROOT)/runtime/closure_templates.h
	cc -g -c $(INCLUDES) $<

mkfs: mkfs.o $(UNIXRUNTIME)
	cc $^ -g -o mkfs

dump: dump.o $(UNIXRUNTIME)
	cc $^ -g -o mkfs

clean:
	rm -f *.o mkfs

