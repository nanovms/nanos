include ../../vars.mk

# these are built for the target platform (Linux x86_64)
DEBUG_STRIP=y
PROGRAMS= \
	aio \
	aslr \
	dup \
	creat \
	epoll \
	eventfd \
	fallocate \
	fadvise \
	fcntl \
	fst \
	fs_full \
	ftrace \
	futex \
	futexrobust \
	getdents \
	getrandom \
	hw \
	hwg \
	hws \
	ktest \
	inotify \
	io_uring \
	mkdir \
	mmap \
	netlink \
	netsock \
	nullpage \
	paging \
	pipe \
	readv \
	rename \
	sandbox \
	sendfile \
	sigoverflow \
	signal \
	socketpair \
	symlink \
	syslog \
	thread_test \
	time \
	tlbshootdown \
	tun \
	udploop \
	unixsocket \
	unlink \
	web \
	webg \
	webs \
	write \
	writev

SRCS-aio= \
	$(CURDIR)/aio.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-aio=	-static

SRCS-aslr= \
	$(CURDIR)/aslr.c \
	$(SRCDIR)/unix_process/ssp.c

SRCS-dup= \
	$(CURDIR)/dup.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-dup=		-static

SRCS-creat= \
	$(CURDIR)/creat.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-creat=		-static

SRCS-epoll= \
	$(CURDIR)/epoll.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-epoll=		-static
LIBS-epoll=			-lpthread

SRCS-eventfd= \
	$(CURDIR)/eventfd.c \
	$(SRCDIR)/unix_process/ssp.c

LDFLAGS-eventfd=	-static
LIBS-eventfd=		-lpthread

SRCS-fallocate= \
	$(CURDIR)/fallocate.c \
	$(SRCDIR)/unix_process/ssp.c

LDFLAGS-fallocate=	-static

SRCS-fadvise= \
	$(CURDIR)/fadvise.c \
	$(SRCDIR)/unix_process/ssp.c

LDFLAGS-fadvise=	-static

SRCS-fcntl= \
	$(CURDIR)/fcntl.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-fcntl=		-static

SRCS-fs_full= \
	$(CURDIR)/fs_full.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-fs_full=	-static

SRCS-ftrace= \
	$(CURDIR)/ftrace.c \
	$(SRCDIR)/unix_process/ssp.c

LDFLAGS-ftrace=	-static

SRCS-futexrobust= \
	$(CURDIR)/futexrobust.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-futexrobust=		-static
LIBS-futexrobust=			-lpthread

SRCS-futex= \
	$(CURDIR)/futex.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-futex=	-static
LIBS-futex=	-lpthread

SRCS-getdents=		$(CURDIR)/getdents.c
LDFLAGS-getdents=	-static

SRCS-getrandom=		$(CURDIR)/getrandom.c
LDFLAGS-getrandom=	-static
LIBS-getrandom=		-lm

SRCS-hw=		$(CURDIR)/hw.c

SRCS-hws=		$(SRCS-hw)
LDFLAGS-hws=		-static

SRCS-inotify= \
	$(CURDIR)/inotify.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-inotify=	-static
LIBS-inotify=		-lpthread

SRCS-io_uring= \
	$(CURDIR)/io_uring.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-io_uring=	-static

SRCS-ktest=		$(CURDIR)/ktest.c
LDFLAGS-ktest=		-static

SRCS-mmap= \
	$(CURDIR)/mmap.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(RUNTIME)
LDFLAGS-mmap=		-static
LIBS-mmap=		-lpthread

SRCS-mkdir= \
	$(CURDIR)/mkdir.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-mkdir=		-static

SRCS-netlink= \
	$(CURDIR)/netlink.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-netlink=	-static

SRCS-netsock= \
	$(CURDIR)/netsock.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-netsock=	-static
LIBS-netsock=		-lpthread

SRCS-nullpage=		$(CURDIR)/nullpage.c
# use -O0 so that clang does not generate UD2 instruction for the code with undefined behavior
CFLAGS-nullpage.c=	-O0
LDFLAGS-nullpage=	-static

SRCS-paging=		$(CURDIR)/paging.c
LDFLAGS-paging=		-static

SRCS-pipe= \
	$(CURDIR)/pipe.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(RUNTIME)

LDFLAGS-pipe=		-static
LIBS-pipe=		-lm -lpthread

SRCS-rename= \
	$(CURDIR)/rename.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-rename=		-static

SRCS-sendfile=		$(CURDIR)/sendfile.c
LDFLAGS-sendfile=	-static

SRCS-sandbox= \
	$(CURDIR)/sandbox.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-sandbox=	-static

SRCS-sigoverflow= \
	$(CURDIR)/sigoverflow.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(RUNTIME)
LDFLAGS-sigoverflow=	-static
LIBS-sigoverflow=	-lpthread

SRCS-signal= \
	$(CURDIR)/signal.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(RUNTIME)
LDFLAGS-signal=		-static
LIBS-signal=		-lm -lpthread

SRCS-socketpair= \
	$(CURDIR)/socketpair.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-socketpair=	-static
LIBS-socketpair=	-lpthread

SRCS-symlink= \
	$(CURDIR)/symlink.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-symlink=	-static

SRCS-syslog= \
	$(CURDIR)/syslog.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-syslog=	-static

SRCS-thread_test= \
	$(SRCDIR)/unix_process/ssp.c\
	$(CURDIR)/thread_test.c 
LDFLAGS-thread_test=	-static
LIBS-thread_test=	-lpthread

SRCS-time= \
	$(CURDIR)/time.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-time=		-static
LIBS-time=		-lrt -lpthread

SRCS-tlbshootdown= \
	$(CURDIR)/tlbshootdown.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(RUNTIME)
LDFLAGS-tlbshootdown=		-static
LIBS-tlbshootdown=	-lpthread

SRCS-tun= \
	$(CURDIR)/tun.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-tun=	-static

SRCS-udploop= \
	$(CURDIR)/udploop.c \
	$(SRCDIR)/http/http.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c \
	$(RUNTIME)
LDFLAGS-udploop=	 -static

SRCS-unixsocket= \
	$(CURDIR)/unixsocket.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-unixsocket=	-static
LIBS-unixsocket=	-lpthread

SRCS-unlink= \
	$(CURDIR)/unlink.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-unlink=		-static

SRCS-web= \
	$(CURDIR)/web.c \
	$(SRCDIR)/http/http.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c \
	$(RUNTIME)

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

ifeq ($(ARCH),x86_64)

PROGRAMS+= \
	umcg \
	vsyscall \

SRCS-umcg= \
	$(CURDIR)/umcg.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(RUNTIME)
LIBS-umcg=	-lpthread

SRCS-vsyscall= \
	$(CURDIR)/vsyscall.c \
	$(SRCDIR)/unix_process/ssp.c
LDFLAGS-vsyscall=	 -static

endif

CFLAGS+=	-O3 -DENABLE_MSG_DEBUG
CFLAGS+=	-I$(ARCHDIR) \
		-I$(SRCDIR) \
		-I$(SRCDIR)/http \
		-I$(SRCDIR)/kernel \
		-I$(SRCDIR)/runtime \
		-I$(SRCDIR)/unix \
		-I$(SRCDIR)/unix_process

CLEANDIRS+=	$(OBJDIR)/test

all: $(PROGRAMS)

dummy:

.PHONY: dummy

include ../../rules.mk

TARGET_ROOT=	$(NANOS_TARGET_ROOT)
ifeq ($(UNAME_s),Darwin)
ifeq ($(ARCH),x86_64)
GCC_VER=	6
OBJS_CRTBEGIN_D=-dynamic-linker /lib64/ld-linux-x86-64.so.2
LD=			x86_64-elf-ld
else ifeq ($(ARCH),aarch64)
GCC_VER=	12
OBJS_CRTBEGIN_D=-dynamic-linker /lib/ld-linux-aarch64.so.1
LD=			aarch64-linux-ld
endif
# crtbegin/crtend for dynamically linked executables
OBJS_CRTBEGIN_D+= $(TARGET_ROOT)/usr/lib/$(ARCH)-linux-gnu/Scrt1.o $(TARGET_ROOT)/usr/lib/$(ARCH)-linux-gnu/crti.o $(TARGET_ROOT)/usr/lib/gcc/$(ARCH)-linux-gnu/$(GCC_VER)/crtbeginS.o
OBJS_CRTEND_D=	-L=/usr/lib/$(ARCH)-linux-gnu -L=/usr/lib/gcc/$(ARCH)-linux-gnu/$(GCC_VER) -lc $(TARGET_ROOT)/usr/lib/gcc/$(ARCH)-linux-gnu/$(GCC_VER)/crtendS.o $(TARGET_ROOT)/usr/lib/$(ARCH)-linux-gnu/crtn.o
# crtbegin/crtend for statically linked executables
OBJS_CRTBEGIN=	$(TARGET_ROOT)/usr/lib/$(ARCH)-linux-gnu/crt1.o $(TARGET_ROOT)/usr/lib/$(ARCH)-linux-gnu/crti.o $(TARGET_ROOT)/usr/lib/gcc/$(ARCH)-linux-gnu/$(GCC_VER)/crtbeginT.o
OBJS_CRTEND=	-L=/usr/lib/$(ARCH)-linux-gnu -L=/usr/lib -L=/lib/$(ARCH)-linux-gnu -L=/lib -L=/usr/lib/gcc/$(ARCH)-linux-gnu/$(GCC_VER) --start-group -lgcc -lgcc_eh -lc --end-group $(TARGET_ROOT)/usr/lib/gcc/$(ARCH)-linux-gnu/$(GCC_VER)/crtend.o $(TARGET_ROOT)/usr/lib/$(ARCH)-linux-gnu/crtn.o
endif

ifneq ($(CROSS_COMPILE),)
LDFLAGS+=	--sysroot=$(TARGET_ROOT)
ifeq ($(findstring clang,$(COMPILER_VERSION)),clang)
CFLAGS+=	-target x86_64-elf --sysroot $(TARGET_ROOT) -I $(TARGET_ROOT)/usr/include
else
CFLAGS+=	--sysroot $(TARGET_ROOT) -isystem $(TARGET_ROOT)/usr/include -isystem $(TARGET_ROOT)/usr/include/$(ARCH)-linux-gnu
ifeq ($(CC),$(LD))
LDFLAGS+=	-B$(TARGET_ROOT)/usr/lib/$(ARCH)-linux-gnu
endif
endif
ifeq ($(ARCH),riscv64)
LDFLAGS+=	-Wl,--eh-frame-hdr
endif
ifeq ($(UNAME_s),Darwin)
OBJS_BEGIN=	$(OBJS_CRTBEGIN)
OBJS_END=	$(OBJS_CRTEND)

$(PROG-hw): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(PROG-hw): OBJS_END=$(OBJS_CRTEND_D)

$(PROG-web): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(PROG-web): OBJS_END=$(OBJS_CRTEND_D)
endif
endif

ifneq ($(CROSS_COMPILE),)
GO_ENV=		GOOS=linux
ifeq ($(ARCH),aarch64)
GO_ENV+=	GOARCH=arm64
else ifeq ($(ARCH),x86_64)
GO_ENV+=	GOARCH=amd64
else
GO_ENV+=	GOARCH=$(ARCH)
endif
endif
