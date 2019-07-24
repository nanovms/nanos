# these are built for the target platform (Linux x86_64)
PROGRAMS= \
	dup \
	creat \
	eventfd \
	fst \
	getdents \
	getrandom \
	hw \
	hwg \
	hws \
	mkdir \
	nullpage \
	paging \
	pipe \
	rename \
	sendfile \
	signal \
	socketpair \
	time \
	udploop \
	unlink \
	vsyscall \
	web \
	webg \
	webs \
	write \
	writev \
	readv

SRCS-dup= \
	$(CURDIR)/dup.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-dup=		-static

SRCS-creat= \
	$(CURDIR)/creat.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-creat=		-static

SRCS-eventfd= \
	$(CURDIR)/eventfd.c \
	$(SRCDIR)/unix_process/ssp.c

LDFLAGS-eventfd=	-static
LIBS-eventfd=		-lpthread

SRCS-getdents=		$(CURDIR)/getdents.c
LDFLAGS-getdents=	-static

SRCS-getrandom=		$(CURDIR)/getrandom.c
LDFLAGS-getrandom=	-static
LIBS-getrandom=		-lm

SRCS-hw=		$(CURDIR)/hw.c

SRCS-hws=		$(SRCS-hw)
LDFLAGS-hws=		-static

SRCS-mkdir= \
	$(CURDIR)/mkdir.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-mkdir=		-static

SRCS-nullpage=		$(CURDIR)/nullpage.c
# use -O0 so that clang does not generate UD2 instruction for the code with undefined behavior
CFLAGS-nullpage.c=	-O0
LDFLAGS-nullpage=	-static

SRCS-paging=		$(CURDIR)/paging.c
LDFLAGS-paging=		-static

SRCS-pipe= \
	$(CURDIR)/pipe.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/crypto/chacha.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/debug_heap.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/heap/mcache.c
LDFLAGS-pipe=		-static
LIBS-pipe=		-lm -lpthread

SRCS-rename= \
	$(CURDIR)/rename.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-rename=		-static

SRCS-sendfile=		$(CURDIR)/sendfile.c
LDFLAGS-sendfile=	-static

SRCS-signal= \
	$(CURDIR)/signal.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/crypto/chacha.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/debug_heap.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/heap/mcache.c
LDFLAGS-signal=		-static
LIBS-signal=		-lm -lpthread

SRCS-socketpair= \
	$(CURDIR)/socketpair.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-socketpair=	-static
LIBS-socketpair=	-lpthread

SRCS-time= \
	$(CURDIR)/time.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-time=		-static

SRCS-udploop= \
	$(CURDIR)/udploop.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/http.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/debug_heap.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/heap/mcache.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/sha256.c \
	$(SRCDIR)/runtime/signature.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/crypto/chacha.c
LDFLAGS-udploop=	 -static

SRCS-unlink= \
	$(CURDIR)/unlink.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-unlink=		-static

SRCS-vsyscall= \
	$(CURDIR)/vsyscall.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-vsyscall=	 -static

SRCS-web= \
	$(CURDIR)/web.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/http.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c \
	$(SRCDIR)/runtime/bitmap.c \
	$(SRCDIR)/runtime/buffer.c \
	$(SRCDIR)/runtime/extra_prints.c \
	$(SRCDIR)/runtime/format.c \
	$(SRCDIR)/runtime/heap/id.c \
	$(SRCDIR)/runtime/heap/freelist.c \
	$(SRCDIR)/runtime/heap/debug_heap.c \
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/runtime/heap/mcache.c \
	$(SRCDIR)/runtime/memops.c \
	$(SRCDIR)/runtime/merge.c \
	$(SRCDIR)/runtime/pqueue.c \
	$(SRCDIR)/runtime/random.c \
	$(SRCDIR)/runtime/range.c \
	$(SRCDIR)/runtime/runtime_init.c \
	$(SRCDIR)/runtime/sha256.c \
	$(SRCDIR)/runtime/signature.c \
	$(SRCDIR)/runtime/string.c \
	$(SRCDIR)/runtime/symbol.c \
	$(SRCDIR)/runtime/table.c \
	$(SRCDIR)/runtime/timer.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(SRCDIR)/runtime/tuple.c \
	$(SRCDIR)/runtime/crypto/chacha.c

SRCS-webs=		$(SRCS-web)
LDFLAGS-webs=		-static

SRCS-write= \
	$(CURDIR)/write.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-write=		-static

SRCS-writev= \
        $(CURDIR)/writev.c \
        $(SRCDIR)/unix_process/ssp.c
LDFLAGS-writev=          -static

SRCS-readv = \
	$(CURDIR)/readv.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-readv=		-static

CFLAGS+=	-DENABLE_MSG_DEBUG
CFLAGS+=	-I$(SRCDIR)/runtime \
		-I$(SRCDIR)/unix \
		-I$(SRCDIR)/unix_process \
		-I$(SRCDIR)/x86_64

CLEANDIRS+=	$(OBJDIR)/test

all: $(PROGRAMS)

include ../../rules.mk

ifeq ($(UNAME_s),Darwin)
CFLAGS+=	-target x86_64-elf --sysroot $(TARGET_ROOT)
LD=		x86_64-elf-ld
LDFLAGS+=	--sysroot=$(TARGET_ROOT)
OBJS_BEGIN=	$(OBJS_CRTBEGIN)
OBJS_END=	$(OBJS_CRTEND)
GO_ENV=		GOOS=linux GOARCH=amd64

$(PROG-hw): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(PROG-hw): OBJS_END=$(OBJS_CRTEND_D)

$(PROG-web): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(PROG-web): OBJS_END=$(OBJS_CRTEND_D)
endif
