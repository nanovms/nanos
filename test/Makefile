include ../config.mk
include ../common.mk

OUT = $(ROOT)/output/test

CFLAGS += -g -std=gnu99
#CFLAGS+=-DENABLE_MSG_DEBUG -DID_HEAP_DEBUG

all: objcache_test network_test id_heap_test path_test bitmap_test

unit-test: objcache_test id_heap_test path_test bitmap_test
	$(OBJCACHE_TEST)
	$(ID_HEAP_TEST)
	$(PATH_TEST)

objcache_test: $(OBJCACHE_TEST)

id_heap_test: $(ID_HEAP_TEST)

path_test: $(PATH_TEST)

network_test: $(NETWORK_TEST)

bitmap_test: $(BITMAP_TEST)

includes := \
	-I$(SRC)/runtime \
	-I$(SRC)/tfs \
	-I$(SRC)/unix_process \
	-I$(SRC)/x86_64 \

RUNTIMESRC += $(SRC)/runtime/bitmap.c
RUNTIMESRC += $(SRC)/runtime/buffer.c
RUNTIMESRC += $(SRC)/runtime/extra_prints.c
RUNTIMESRC += $(SRC)/runtime/format.c
RUNTIMESRC += $(SRC)/runtime/heap/id.c
RUNTIMESRC += $(SRC)/runtime/heap/objcache.c
RUNTIMESRC += $(SRC)/runtime/merge.c
RUNTIMESRC += $(SRC)/runtime/pqueue.c
RUNTIMESRC += $(SRC)/runtime/random.c
RUNTIMESRC += $(SRC)/runtime/rtrie.c
RUNTIMESRC += $(SRC)/runtime/runtime_init.c
RUNTIMESRC += $(SRC)/runtime/sha256.c
RUNTIMESRC += $(SRC)/runtime/symbol.c
RUNTIMESRC += $(SRC)/runtime/table.c
RUNTIMESRC += $(SRC)/runtime/timer.c
RUNTIMESRC += $(SRC)/runtime/tuple.c
RUNTIMESRC += $(SRC)/tfs/tfs.c
RUNTIMESRC += $(SRC)/tfs/tlog.c
RUNTIMESRC += $(SRC)/unix_process/unix_process_runtime.c
RUNTIMESRC += $(SRC)/unix_process/mmap_heap.c


objcache_test-srcs := \
	$(ROOT)/test/objcache_test.c \
	$(RUNTIMESRC)

objcache_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),objcache_test)

network_test-srcs := \
	$(ROOT)/test/network_test.c \
	$(RUNTIMESRC) \

network_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),objcache_test)

id_heap_test-srcs := \
	$(ROOT)/test/id_heap_test.c \
	$(RUNTIMESRC) \

id_heap_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),objcache_test)

path_test-srcs := \
	$(ROOT)/test/path_test.c \
	$(RUNTIMESRC) \

path_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),objcache_test)

bitmap_test-srcs := \
	$(ROOT)/test/bitmap_test.c \
	$(RUNTIMESRC) \

bitmap_test-objs = $(call srcs-to-objs,$(ROOT),$(OUT),objcache_test)

$(objcache_test-objs): $(CLOSURE_TMPL)
$(network_test-objs): $(CLOSURE_TMPL)
$(id_heap_test-objs): $(CLOSURE_TMPL)
$(path_test-objs): $(CLOSURE_TMPL)
$(bitmap_test-objs): $(CLOSURE_TMPL)

$(OBJCACHE_TEST): $(objcache_test-objs)
	$(call cmd,host-prog)

$(NETWORK_TEST): $(network_test-objs)
	$(call cmd,host-prog)

$(ID_HEAP_TEST): $(id_heap_test-objs)
	$(call cmd,host-prog)

$(PATH_TEST): $(path_test-objs)
	$(call cmd,host-prog)

$(BITMAP_TEST): $(bitmap_test-objs)
	$(call cmd,host-prog)

clean-objs = \
	$(id_heap_test-objs) $(ID_HEAP_TEST) \
	$(network_test-objs) $(NETWORK_TEST) \
	$(objcache_test-objs) $(OBJCACHE_TEST) \
	$(path_test-objs) $(PATH_TEST) \
	$(bitmap_test-objs) $(BITMAP_TEST) \
	$(CLOSURE_TMPL) \

clean: default-clean

.PHONY: objcache_test network_test id_heap_test path_test bitmap_test

include ../rules.mk