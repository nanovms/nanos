
all:objcache_test

ROOT=$(PWD)/..

INCLUDES = -include def64.h
include $(ROOT)/runtime/Makefile
INCLUDES += -I$(ROOT)/x86_64
include $(ROOT)/tfs/Makefile

%.o: %.c $(ROOT)/runtime/closure_templates.h
	cc -g -c $(INCLUDES) $<

objcache_test: objcache_test.o $(UNIXRUNTIME) $(TFS)
	cc $^ -g -o objcache_test
clean:
	rm -f *.o test

