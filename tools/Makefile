override ARCH=$(shell uname -m)
override CROSS_COMPILE=
CONTGEN=$(OBJDIR)/bin/contgen
PROGRAMS=dump mkfs vdsogen
ADDITIONAL_PROGRAMS=tfs-fuse

SRCS-dump= \
	$(CURDIR)/dump.c \
	$(SRCDIR)/kernel/pagecache.c \
	$(RUNTIME) \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-tfs-fuse= \
	$(CURDIR)/tfs-fuse.c \
	$(SRCDIR)/kernel/pagecache.c \
	$(RUNTIME) \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c
LIBS-tfs-fuse=	-lfuse -lpthread

SRCS-mkfs= \
	$(SRCDIR)/kernel/pagecache.c \
	$(CURDIR)/mkfs.c \
	$(RUNTIME) \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-vdsogen=	$(CURDIR)/vdsogen.c

CFLAGS+=-I$(ARCHDIR) \
	-I$(SRCDIR) \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/tfs \
	-I$(SRCDIR)/unix_process

all: $(PROGRAMS)

include ../rules.mk

contgen: $(CONTGEN)

$(CONTGEN): $(CURDIR)/contgen.c
	@$(MKDIR) $(dir $@)
	$(CC) $(DEPFLAGS) -std=gnu11 -O3 $< -o $@

CLEANFILES+=	$(CONTGEN) $(TOOLDIR)/contgen.d
