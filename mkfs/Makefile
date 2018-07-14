
all:mkfs dump

ROOT=$(PWD)/..

INCLUDES = -include def64.h
include $(ROOT)/runtime/Makefile
INCLUDES += -I$(ROOT)/x86_64
include $(ROOT)/tfs/Makefile

%.o: %.c $(ROOT)/runtime/closure_templates.h
	cc -g -c $(INCLUDES) $<

mkfs: mkfs.o $(UNIXRUNTIME) $(TFS)
	cc $^ -g -o mkfs

dump: dump.o $(UNIXRUNTIME) $(TFS)
	cc $^ -g -o dump

clean:
	rm -f *.o mkfs

