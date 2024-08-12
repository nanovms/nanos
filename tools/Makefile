include ../vars.mk

override ARCH=$(shell uname -m)
override CROSS_COMPILE=
ifeq ($(shell uname -s),Darwin)
override CC=cc
endif
CONTGEN=$(OBJDIR)/bin/contgen
PROGRAMS=dump mkfs vdsogen
ADDITIONAL_PROGRAMS=tfs-fuse

SRCS-dump= \
	$(CURDIR)/dump.c \
	$(RUNTIME) \
	$(SRCDIR)/fs/fs.c \
	$(SRCDIR)/fs/tfs.c \
	$(SRCDIR)/fs/tlog.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-tfs-fuse= \
	$(CURDIR)/tfs-fuse.c \
	$(RUNTIME) \
	$(SRCDIR)/fs/fs.c \
	$(SRCDIR)/fs/tfs.c \
	$(SRCDIR)/fs/tlog.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c
LIBS-tfs-fuse=	-lfuse -lpthread

SRCS-mkfs= \
	$(CURDIR)/mkfs.c \
	$(RUNTIME) \
	$(SRCDIR)/fs/fs.c \
	$(SRCDIR)/fs/tfs.c \
	$(SRCDIR)/fs/tlog.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-vdsogen=	$(CURDIR)/vdsogen.c

CFLAGS+=-O3 \
	-I$(ARCHDIR) \
	-I$(SRCDIR) \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/fs \
	-I$(SRCDIR)/unix_process

all: $(PROGRAMS)

include ../rules.mk

contgen: $(CONTGEN)

$(CONTGEN): $(CURDIR)/contgen.c
	@$(MKDIR) $(dir $@)
	$(CC) $(DEPFLAGS) -std=gnu11 -O3 $< -o $@

CLEANFILES+=	$(CONTGEN) $(TOOLDIR)/contgen.d
