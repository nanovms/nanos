
all:objcache_test

ROOT=$(PWD)/..

CC=cc
CFLAGS=-g -c -DENABLE_MSG_DEBUG

INCLUDES = -include def64.h
include $(ROOT)/runtime/Makefile
INCLUDES += -I$(ROOT)/x86_64
include $(ROOT)/tfs/Makefile

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) $(CFLAGS) $(INCLUDES) $<

objcache_test: objcache_test.o $(UNIXRUNTIME) $(TFS)
	$(CC) $^ -g -o objcache_test
clean:
	rm -f *.o test

