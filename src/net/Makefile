lwip:
	(cd $(ROOT)/net; git clone http://git.savannah.nongnu.org/git/lwip.git ; cd lwip ; git checkout STABLE-2_0_3_RELEASE)

LWIPDIR	:= lwip/src
include $(ROOT)/net/lwip/src/Filelists.mk

includes += \
	-I$(ROOT)/net/$(LWIPDIR)/include \
	-I$(ROOT)/net

core-objs := $(patsubst %.c,%.o,$(COREFILES))
core4-objs := $(patsubst %.c,%.o,$(CORE4FILES))

netif-objs := \
	$(LWIPDIR)/netif/ethernet.o \
	$(LWIPDIR)/netif/ethernetif.o \

net-objs := \
	$(core-objs) \
	$(core4-objs) \
	$(netif-objs) \
	netsyscall.o \
	net.o \
