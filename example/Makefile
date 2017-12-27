
all:app
ROOT=..

include $(ROOT)/runtime/Makefile
include $(ROOT)/virtio/Makefile

LWIPDIR=$(ROOT)/lwip/src
include $(LWIPDIR)/Filelists.mk
INCLUDES += -I$(LWIPDIR)/include -I.
VPATH +=$(LWIPDIR)/core
VPATH +=$(LWIPDIR)/core/ipv4
VPATH +=$(LWIPDIR)/netif

INCLUDES += -I$(ROOT)/musl/include
INCLUDES += -I$(ROOT)/musl/obj/include

COREOBJ := $(addsuffix .o, $(basename $(notdir $(COREFILES))))
CORE4OBJ := $(addsuffix .o, $(basename $(notdir $(CORE4FILES))))

# put in a proper library build

.c.o:
	cc $(INCLUDES) -nostdinc -fno-stack-protector $< -c

OBJS = $(RUNTIME) $(VIRTIO) $(COREOBJ) $(CORE4OBJ) ethernet.o

app: $(OBJS) app.c
	cc app.c -Wl,"-e_start"  -nostdlib -L$(ROOT)/musl/lib -lc $(INCLUDES) $(OBJS) -o app

clean:
	rm -f app *.o *~


