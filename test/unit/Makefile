include ../../config.mk
include ../../common.mk

OUT = $(ROOT)/output/test/unit
TESTSRC = $(ROOT)/test/unit

CFLAGS  = -fno-stack-protector
CFLAGS  += -fdata-sections -ffunction-sections
CFLAGS  += $(includes)
CFLAGS  += -g -std=gnu11 -DHOST_BUILD $(CFLAG_WARNINGS) -Wformat $(PLATFORM_CFLAGS)
ifeq ($(UNAME_s),Darwin)
CFLAGS  += -DNO_EPOLL
endif
#CFLAGS+=-DENABLE_MSG_DEBUG -DID_HEAP_DEBUG

# gcov support
CFLAGS  += -fprofile-arcs -ftest-coverage
HOSTLDFLAGS  += -fprofile-arcs
GCOVOUT = $(OUT)/test/unit

all: objcache_test network_test id_heap_test path_test pqueue_test vector_test udp_test buffer_test range_test tuple_test

test: objcache_test id_heap_test path_test pqueue_test vector_test buffer_test range_test tuple_test
	$(OBJCACHE_TEST)
	$(ID_HEAP_TEST)
	$(PATH_TEST)
	$(PQUEUE_TEST)
	$(VECTOR_TEST)
	$(BUFFER_TEST)
	$(RANGE_TEST)
	$(TUPLE_TEST)

gcov: objcache_test id_heap_test path_test pqueue_test vector_test buffer_test range_test tuple_test
	gcov -o $(GCOVOUT) $(OBJCACHE_TEST)
	gcov -o $(GCOVOUT) $(ID_HEAP_TEST)
	gcov -o $(GCOVOUT) $(PATH_TEST)
	gcov -o $(GCOVOUT) $(PQUEUE_TEST)
	gcov -o $(GCOVOUT) $(VECTOR_TEST)
	gcov -o $(GCOVOUT) $(BUFFER_TEST)
	gcov -o $(GCOVOUT) $(RANGE_TEST)
	gcov -o $(GCOVOUT) $(TUPLE_TEST)
	lcov --capture --directory ../.. --output-file gcov-tests.info
	mkdir -p $(OUT)/gcov
	genhtml gcov-tests.info --output-directory $(OUT)/gcov

objcache_test: $(OBJCACHE_TEST)

id_heap_test: $(ID_HEAP_TEST)

path_test: $(PATH_TEST)

network_test: $(NETWORK_TEST)

pqueue_test: $(PQUEUE_TEST)

vector_test: $(VECTOR_TEST)

udp_test: $(UDP_TEST)

buffer_test: $(BUFFER_TEST)

range_test: $(RANGE_TEST)

tuple_test: $(TUPLE_TEST)

includes := \
	-I$(SRC)/runtime \
	-I$(SRC)/tfs \
	-I$(SRC)/unix_process \
	-I$(SRC)/unix \
	-I$(SRC)/x86_64 \

objcache_test-srcs := \
	$(TESTSRC)/objcache_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/heap/objcache.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/sha256.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \

objcache_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),objcache_test)

network_test-srcs := \
	$(TESTSRC)/network_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \
	$(SRC)/unix_process/http.c \
	$(SRC)/unix_process/socket_user.c \
	$(SRC)/unix_process/tiny_heap.c \

network_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),network_test)

id_heap_test-srcs := \
	$(TESTSRC)/id_heap_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \

id_heap_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),id_heap_test)

path_test-srcs := \
	$(TESTSRC)/path_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/sha256.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix/path.c \

path_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),path_test)

pqueue_test-srcs := \
	$(TESTSRC)/pqueue_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/unix_process/unix_process_runtime.c \

pqueue_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),pqueue_test)

vector_test-srcs := \
	$(TESTSRC)/vector_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/unix_process/unix_process_runtime.c \

vector_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),vector_test)

udp_test-srcs := \
	$(TESTSRC)/udp_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \
	$(SRC)/unix_process/http.c \
	$(SRC)/unix_process/socket_user.c \
	$(SRC)/unix_process/tiny_heap.c \

udp_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),udp_test)

buffer_test-srcs := \
	$(TESTSRC)/buffer_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/unix_process/unix_process_runtime.c

buffer_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),buffer_test)

range_test-srcs := \
	$(TESTSRC)/range_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/string.c \
	$(SRC)/unix_process/unix_process_runtime.c \

range_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),range_test)

tuple_test-srcs := \
		$(TESTSRC)/tuple_test.c \
		$(SRC)/runtime/bitmap.c \
		$(SRC)/runtime/buffer.c \
		$(SRC)/runtime/extra_prints.c \
		$(SRC)/runtime/format.c \
		$(SRC)/runtime/heap/id.c \
		$(SRC)/runtime/merge.c \
		$(SRC)/runtime/pqueue.c \
		$(SRC)/runtime/random.c \
		$(SRC)/runtime/runtime_init.c \
		$(SRC)/runtime/symbol.c \
		$(SRC)/runtime/table.c \
		$(SRC)/runtime/timer.c \
		$(SRC)/runtime/tuple.c \
		$(SRC)/runtime/string.c \
		$(SRC)/unix_process/unix_process_runtime.c

tuple_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),tuple_test)

$(objcache_test-objs): $(CLOSURE_TMPL)
$(network_test-objs): $(CLOSURE_TMPL)
$(id_heap_test-objs): $(CLOSURE_TMPL)
$(path_test-objs): $(CLOSURE_TMPL)
$(pqueue_test-objs): $(CLOSURE_TMPL)
$(vector_test-objs): $(CLOSURE_TMPL)
$(udp_test-objs): $(CLOSURE_TMPL)
$(buffer_test-objs): $(CLOSURE_TMPL)
$(range_test-objs): $(CLOSURE_TMPL)
$(tuple_test-objs): $(CLOSURE_TMPL)

$(OBJCACHE_TEST): $(objcache_test-objs)
	$(call cmd,host-prog)

$(NETWORK_TEST): $(network_test-objs)
	$(call cmd,host-prog)

$(ID_HEAP_TEST): $(id_heap_test-objs)
	$(call cmd,host-prog)

$(PATH_TEST): $(path_test-objs)
	$(call cmd,host-prog)

$(PQUEUE_TEST): $(pqueue_test-objs)
	$(call cmd,host-prog)

$(VECTOR_TEST): $(vector_test-objs)
	$(call cmd,host-prog)

$(UDP_TEST): $(udp_test-objs)
	$(call cmd,host-prog)

$(BUFFER_TEST): $(buffer_test-objs)
	$(call cmd,host-prog)

$(RANGE_TEST): $(range_test-objs)
	$(call cmd,host-prog)

$(TUPLE_TEST): $(tuple_test-objs)
	$(call cmd,host-prog)

clean-objs = \
	$(id_heap_test-objs) $(ID_HEAP_TEST) \
	$(network_test-objs) $(NETWORK_TEST) \
	$(objcache_test-objs) $(OBJCACHE_TEST) \
	$(path_test-objs) $(PATH_TEST) \
	$(pqueue_test-objs) $(PQUEUE_TEST) \
	$(vector_test-objs) $(VECTOR_TEST) \
	$(udp_test-objs) $(UDP_TEST) \
	$(buffer_test-objs) $(BUFFER_TEST) \
	$(range_test-objs) $(RANGE_TEST) \
	$(tuple_test-objs) $(TUPLE_TEST) \
	$(CLOSURE_TMPL) \

clean-gc = $(call objs-to-gc,$(OUT),$(clean-objs))

gcov-clean:
	$(Q) $(RM) -f $(clean-gc)

clean: gcov-clean default-clean

.PHONY: objcache_test network_test id_heap_test path_test pqueue_test vector_test udp_test buffer_test range_test tuple_test

include ../../rules.mk
