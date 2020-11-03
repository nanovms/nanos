PROGRAMS=	test

SRCS-test= \
	$(CURDIR)/test.c

CFLAGS+=	$(KERNCFLAGS) -I$(CURDIR) -fPIC
LDFLAGS+=	-pie -nostdlib -DKLIB -T$(ARCHDIR)/klib.lds

ifeq ($(ARCH),x86_64)
CFLAGS+=	-mcmodel=kernel
endif

all: $(PROGRAMS)

include ../rules.mk
