ROOT=$(PWD)/..
CC=cc
GO=go
CFLAGS=-g -c -DENABLE_MSG_DEBUG -std=gnu99 

include $(ROOT)/unix_process/Makefile
VPATH += $(ROOT)/test

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) $(CFLAGS) $(INCLUDES) $<

all: hw webs hwg webg hws webs

hwg: hwg.go
	$(GO) build hwg.go

hw: hw.c
	$(CC) hw.c -o hw

hws: hw.c
	$(CC) hw.c -g -static -o hws

web: web.o http.o socket_user.o $(UNIXRUNTIME)
	$(CC) $^ -g -o web

webs: web.o http.o socket_user.o  $(UNIXRUNTIME)
	$(CC) $^ -static -g -o webs

webg: webg.go
	$(GO) build webg.go

fst: fst.go
	$(GO) build fst.go

clean:
	rm -f *.o *~ hw web hwg webg webs hws


