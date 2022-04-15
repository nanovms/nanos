PROGRAMS= \
	bitmap_test \
	buffer_test \
	closure_test \
	id_heap_test \
	memops_test \
	network_test \
	objcache_test \
	parser_test \
	pqueue_test \
	queue_test \
	range_test \
	random_test \
	rbtree_test \
	table_test \
	tuple_test \
	udp_test \
	vector_test
SKIP_TEST=	network_test udp_test

SRCS-bitmap_test= \
	$(CURDIR)/bitmap_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-buffer_test= \
	$(CURDIR)/buffer_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-closure_test= \
	$(CURDIR)/closure_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-id_heap_test= \
	$(CURDIR)/id_heap_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-memops_test= \
	$(CURDIR)/memops_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-network_test= \
	$(CURDIR)/network_test.c \
	$(SRCDIR)/http/http.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c

SRCS-objcache_test= \
	$(CURDIR)/objcache_test.c \
	$(RUNTIME)\
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c

SRCS-parser_test= \
	$(CURDIR)/parser_test.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-pqueue_test= \
	$(CURDIR)/pqueue_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-queue_test= \
	$(CURDIR)/queue_test.c \
	$(RUNTIME)\
	$(SRCDIR)/runtime/queue.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

LIBS-queue_test=	-lpthread

SRCS-range_test= \
	$(CURDIR)/range_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-random_test = \
	$(CURDIR)/random_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-rbtree_test= \
	$(CURDIR)/rbtree_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-table_test= \
	$(CURDIR)/table_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c

SRCS-tuple_test= \
	$(CURDIR)/tuple_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-udp_test= \
	$(CURDIR)/udp_test.c \
	$(SRCDIR)/http/http.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c

SRCS-vector_test= \
	$(CURDIR)/vector_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c


CFLAGS+=	-O3 \
		-I$(ARCHDIR) \
		-I$(SRCDIR) \
		-I$(SRCDIR)/http \
		-I$(SRCDIR)/kernel \
		-I$(SRCDIR)/runtime \
		-I$(SRCDIR)/unix_process \
		-I$(SRCDIR)/unix \
#CFLAGS+=	-DENABLE_MSG_DEBUG -DID_HEAP_DEBUG

CLEANDIRS+=	$(OBJDIR)/test

# gcov support
CFLAGS+=	-fprofile-arcs -ftest-coverage
LDFLAGS+=	-fprofile-arcs
GCDAFILES=	$(sort $(foreach p,$(PROGRAMS),$(patsubst %.o,%.gcda,$(OBJS-$p))))
GCOVFILES=	$(sort $(foreach p,$(PROGRAMS),$(patsubst %.o,%.gcno,$(OBJS-$p))))
GCOVFILES+=	$(GCDAFILES) $(OBJDIR)/gcov-tests.info
CLEANFILES+=	$(GCOVFILES)

all: $(PROGRAMS)

.PHONY: test gcov gcov-clean

test: all
	$(Q) $(RM) $(GCDAFILES)
	$(foreach p,$(filter-out $(SKIP_TEST),$(PROGRAMS)),$(call execute_command,$(PROG-$p)))

gcov: test
	$(foreach p,$(PROGRAMS),$(call execute_command,$(GCOV) -o $(OBJDIR)/test/unit $(PROG-$p)))
	$(LCOV) --capture --directory $(ROOTDIR) --output-file $(OBJDIR)/gcov-tests.info
	$(MKDIR) $(OBJDIR)/gcov
	$(GENHTML) $(OBJDIR)/gcov-tests.info --output-directory $(OBJDIR)/gcov

pre-clean:
	$(Q) $(RM) -r $(OBJDIR)/gcov

gcov-clean:
	$(Q) $(RM) $(GCOVFILES)

include ../../rules.mk

ifeq ($(UNAME_s),Darwin)
CFLAGS+=	-DNO_EPOLL
endif
