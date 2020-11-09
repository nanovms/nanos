PROGRAMS=	test

SRCS-test= \
	$(CURDIR)/test.c

all: $(PROGRAMS)

include ../rules.mk

ifeq ($(UNAME_s),Darwin)
ELF_TARGET=     -target x86_64-elf
CFLAGS+=        $(ELF_TARGET)
LD=             x86_64-elf-ld
OBJDUMP=        x86_64-elf-objdump
else
LD=             $(CROSS_COMPILE)ld
endif

CFLAGS+=	$(KERNCFLAGS) -I$(CURDIR) -fPIC -DKLIB

# TODO should add stack protection to klibs...
CFLAGS+=	-fno-stack-protector
LDFLAGS+=	-pie -nostdlib -T$(ARCHDIR)/klib.lds
