
all:objcache_test network_test id_heap_test

ROOT=$(PWD)/..

CC ?= cc
CFLAGS=-g -std=gnu99
#CFLAGS+=-DENABLE_MSG_DEBUG -DID_HEAP_DEBUG

include $(ROOT)/unix_process/Makefile
INCLUDES += -I.

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) -c $(CFLAGS) $(INCLUDES) $<

objcache_test: objcache_test.o $(UNIXRUNTIME) $(TFS)
	$(CC) $(CFLAGS) $^ -g -o objcache_test

network_test: network_test.o $(UNIXRUNTIME)
	$(CC) $(CFLAGS) -I. $^ -g -o network_test

id_heap_test: id_heap_test.o $(UNIXRUNTIME)
	$(CC) $(CFLAGS) $^ -g -o id_heap_test

unit-test: objcache_test id_heap_test
	./objcache_test
	./id_heap_test

clean:
	rm -f *.o objcache_test network_test id_heap_test

