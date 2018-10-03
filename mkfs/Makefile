
all:mkfs dump

ROOT=$(PWD)/..

CC ?= cc

include $(ROOT)/unix_process/Makefile
INCLUDES += -I$(ROOT)/x86_64
include $(ROOT)/tfs/Makefile

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) -g -c $(INCLUDES) $<

mkfs: mkfs.o $(UNIXRUNTIME) $(TFS)
	$(CC) $^ -g -o mkfs

dump: dump.o $(UNIXRUNTIME) $(TFS)
	$(CC) $^ -g -o dump

clean:
	rm -f *.o mkfs

