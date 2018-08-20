
all:objcache_test network_test

ROOT=$(PWD)/..

CC=cc
CFLAGS=-g -c -DENABLE_MSG_DEBUG -std=gnu99 

INCLUDES = -include def64.h
include $(ROOT)/runtime/Makefile
INCLUDES += -I$(ROOT)/x86_64 -I.
include $(ROOT)/tfs/Makefile

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) $(CFLAGS) $(INCLUDES) $<

objcache_test: objcache_test.o $(UNIXRUNTIME) $(TFS)
	$(CC) $^ -g -o objcache_test

network_test: network_test.o http.o socket_user.o $(UNIXRUNTIME)
	$(CC) -I. $^ -g -o network_test

clean:
	rm -f *.o test

