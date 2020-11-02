PROGRAMS=	test

SRCS-test= \
	$(CURDIR)/test.c

CFLAGS+=	$(KERNCFLAGS) -I$(CURDIR) -fPIC

# should prob grab from platform dir
# verify flags, borrowed from vdso build
LDFLAGS+=	-n -pie -nostdlib -shared -DKLIB -T$(ARCHDIR)/klib.lds

all: $(PROGRAMS)

include ../rules.mk
