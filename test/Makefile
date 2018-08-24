
all:objcache_test network_test id_heap_test

ROOT=$(PWD)/..

CC=cc
CFLAGS=-g -c -DENABLE_MSG_DEBUG -std=gnu99 

include $(ROOT)/unix_process/Makefile
INCLUDES += -I.

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) $(CFLAGS) $(INCLUDES) $<

objcache_test: objcache_test.o $(UNIXRUNTIME) $(TFS)
	$(CC) $^ -g -o objcache_test

network_test: network_test.o http.o socket_user.o $(UNIXRUNTIME)
	$(CC) -I. $^ -g -o network_test

id_heap_test: id_heap_test.o $(UNIXRUNTIME)
	$(CC) $^ -g -o id_heap_test

clean:
	rm -f *.o test

