include ../config.mk
include ../common.mk

OUT = $(ROOT)/output/test

CFLAGS += -g -std=gnu99
#CFLAGS+=-DENABLE_MSG_DEBUG -DID_HEAP_DEBUG

all: objcache_test network_test id_heap_test path_test pqueue_test vector_test

unit-test: objcache_test id_heap_test path_test pqueue_test vector_test
	$(OBJCACHE_TEST)
	$(ID_HEAP_TEST)
	$(PATH_TEST)
	$(PQUEUE_TEST)
	$(VECTOR_TEST)

objcache_test: $(OBJCACHE_TEST)

id_heap_test: $(ID_HEAP_TEST)

path_test: $(PATH_TEST)

network_test: $(NETWORK_TEST)

pqueue_test: $(PQUEUE_TEST)

vector_test: $(VECTOR_TEST)

includes := \
	-I$(SRC)/runtime \
	-I$(SRC)/tfs \
	-I$(SRC)/unix_process \
	-I$(SRC)/x86_64 \

objcache_test-srcs := \
	$(ROOT)/test/objcache_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/heap/objcache.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/sha256.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \

objcache_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),objcache_test)

network_test-srcs := \
	$(ROOT)/test/network_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \
	$(SRC)/unix_process/http.c \
	$(SRC)/unix_process/socket_user.c \
	$(SRC)/unix_process/tiny_heap.c \

network_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),network_test)

id_heap_test-srcs := \
	$(ROOT)/test/id_heap_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \

id_heap_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),id_heap_test)

path_test-srcs := \
	$(ROOT)/test/path_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/sha256.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/tfs/tfs.c \
	$(SRC)/tfs/tlog.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/path.c \

path_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),path_test)

pqueue_test-srcs := \
	$(ROOT)/test/pqueue_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/unix_process/unix_process_runtime.c \

pqueue_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),pqueue_test)

vector_test-srcs := \
	$(ROOT)/test/vector_test.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/unix_process/unix_process_runtime.c \

vector_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),vector_test)

$(objcache_test-objs): $(CLOSURE_TMPL)
$(network_test-objs): $(CLOSURE_TMPL)
$(id_heap_test-objs): $(CLOSURE_TMPL)
$(path_test-objs): $(CLOSURE_TMPL)
$(pqueue_test-objs): $(CLOSURE_TMPL)
$(vector_test-objs): $(CLOSURE_TMPL)

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

clean-objs = \
	$(id_heap_test-objs) $(ID_HEAP_TEST) \
	$(network_test-objs) $(NETWORK_TEST) \
	$(objcache_test-objs) $(OBJCACHE_TEST) \
	$(path_test-objs) $(PATH_TEST) \
	$(pqueue_test-objs) $(PQUEUE_TEST) \
	$(vector_test-objs) $(PQUEUE_TEST) \
	$(CLOSURE_TMPL) \

clean: default-clean

.PHONY: objcache_test network_test id_heap_test path_test pqueue_test vector_test

include ../rules.mk
