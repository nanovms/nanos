
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

INCLUDES += -I$(ROOT)/libc/musl/include -I$(ROOT)/libc

COREOBJ := $(addsuffix .o, $(basename $(notdir $(COREFILES))))
CORE4OBJ := $(addsuffix .o, $(basename $(notdir $(CORE4FILES))))

# put in a proper library build

.c.o:
	cc $(INCLUDES) -nostdinc -fno-stack-protector $< -c

OBJS = $(RUNTIME) $(VIRTIO) $(COREOBJ) $(CORE4OBJ) ethernet.o 

$(ROOT)/libc/libc.a:
	cd $(ROOT)/libc; make ROOT=$(ROOT)

app: $(OBJS) app.c $(ROOT)/libc/libc.a
	cc app.c -static -Wl,"-e_start"  -nostdlib $(INCLUDES) $(OBJS) $(ROOT)/libc/libc.a -o app

clean:
	rm -f app *.o *~


