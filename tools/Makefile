override ARCH=$(shell uname -m)
override CROSS_COMPILE=
CONTGEN=$(OBJDIR)/bin/contgen
PROGRAMS=dump mkfs vdsogen

SRCS-dump= \
	$(CURDIR)/dump.c \
	$(SRCDIR)/kernel/pagecache.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/rbtree.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/sg.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/sha256.c \
	$(SRCDIR)/runtime/crypto/chacha.c \
	$(SRCDIR)/tfs/tfs.c \
	$(SRCDIR)/tfs/tlog.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-mkfs= \
	$(SRCDIR)/kernel/pagecache.c \
	$(CURDIR)/mkfs.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/rbtree.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/sg.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/sha256.c \
	$(SRCDIR)/runtime/crypto/chacha.c \
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
