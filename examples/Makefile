ROOT=$(PWD)/..
CC=cc
GO=go
CFLAGS=-g -c -DENABLE_MSG_DEBUG -std=gnu99 -I$(ROOT)/runtime

include $(ROOT)/image.mk
include $(ROOT)/unix_process/Makefile
VPATH += $(ROOT)/test

%.o: %.c $(ROOT)/runtime/closure_templates.h
	$(CC) $(CFLAGS) $(INCLUDES) $<

#  hw.image hwg.image webg.iamge
all: webs.image hws.image webs.image webgs.image net_unit.image 

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

webgs: webg.go
	CGO_ENABLED=0 $(GO) build -a -ldflags '-extldflags "-static"' -o webgs webg.go 

fst: fst.go
	$(GO) build fst.go

net_unit: net_unit.o socket_user.o $(UNIXRUNTIME)
	$(CC) $^ -static -g -o net_unit
clean:
	rm -f *.o *~ hw web hwg webg webs webgs hws *.image fs


