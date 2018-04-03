
ROOT ?= $(PWD)/..

#lwip:
#	git clone http://git.savannah.nongnu.org/git/lwip.git 
#	cd lwip ; git checkout STABLE-2_0_3_RELEASE

LWIPDIR=$(ROOT)/net/lwip/src
include $(ROOT)/net/lwip/src/Filelists.mk

INCLUDES += -I$(LWIPDIR)/include -I$(ROOT)/net
VPATH +=$(LWIPDIR)/core
VPATH +=$(LWIPDIR)/core/ipv4
VPATH +=$(LWIPDIR)/netif
VPATH +=$(ROOT)/net

COREOBJ := $(addsuffix .o, $(basename $(notdir $(COREFILES))))
CORE4OBJ := $(addsuffix .o, $(basename $(notdir $(CORE4FILES))))
NETIF:= ethernet.o ethernetif.o

NETOBJ = $(COREOBJ) $(CORE4OBJ) $(NETIF) netsyscall.o

clean:
 
