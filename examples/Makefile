include ../config.mk
include ../common.mk

OUT = $(ROOT)/output/examples

CFLAGS = -g -DENABLE_MSG_DEBUG $(includes)

all: fst hw hws hwg getdents web webg webgs webs

fst: $(FST)

hw: $(HW)

hws: $(HWS)

hwg: $(HWG)

getdents: $(GETDENTS)

web: $(WEB)

webs: $(WEBS)

webg: $(WEBG)

webgs: $(WEBGS)

write: $(WRITE)

includes := \
	-I$(SRC)/runtime \
	-I$(SRC)/unix_process \
	-I$(SRC)/x86_64 \

hw-srcs := \
	$(ROOT)/examples/hw.c

hw-objs = $(call srcs-to-objs,$(ROOT),$(OUT),hw)

$(HW): $(hw-objs)
	$(call cmd,host-prog)

hws-objs := $(hw-objs)

$(HWS): HOSTLDFLAGS += -static
$(HWS): $(hw-objs)
	$(call cmd,host-prog)

getdents-srcs := \
	$(ROOT)/examples/getdents.c

getdents-objs = $(call srcs-to-objs,$(ROOT),$(OUT),getdents)

$(GETDENTS): HOSTLDFLAGS += -static
$(GETDENTS): $(getdents-objs)

write-srcs := \
	$(ROOT)/examples/write.c

write-objs = $(call srcs-to-objs,$(ROOT),$(OUT),write)

$(WRITE): HOSTLDFLAGS += -static
$(WRITE): $(write-objs)
	$(call cmd,host-prog)

web-srcs := \
	$(ROOT)/examples/web.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \
	$(SRC)/unix_process/http.c \
	$(SRC)/unix_process/path.c \
	$(SRC)/unix_process/socket_user.c \
	$(SRC)/unix_process/tiny_heap.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/heap/freelist.c \
	$(SRC)/runtime/heap/debug_heap.c \
	$(SRC)/runtime/heap/objcache.c \
	$(SRC)/runtime/heap/mcache.c \
	$(SRC)/runtime/merge.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/rtrie.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/sha256.c \
	$(SRC)/runtime/signature.c \
	$(SRC)/runtime/string.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple_parser.c \
	$(SRC)/runtime/tuple.c \

web-objs = $(call srcs-to-objs,$(ROOT),$(OUT),web)

$(WEB): $(web-objs)
	$(call cmd,host-prog)

webs-objs := $(web-objs)

$(WEBS): HOSTLDFLAGS += -static
$(WEBS): $(web-objs)
	$(call cmd,host-prog)

$(WEBGS): webg.go
	@ mkdir -p $(dir $@)
	@ echo "GO	$@"
	$(Q) CGO_ENABLED=0 $(GO) build -a -ldflags '-extldflags "-static"' -o $@ $^

$(hw-objs) $(web-objs): $(CLOSURE_TMPL)

clean-objs = $(hw-objs) $(web-objs) $(FST) $(HW) $(HWG) $(HWS) $(WEB) $(WEBG) $(WEBGS) $(WEBS) $(CLOSURE_TMPL) \
	$(getdents-objs) $(GETDENTS) $(write-objs) $(WRITE)

clean: default-clean

.PHONY: fst hw hwg hws web webg webgs webs getdents write

include ../rules.mk
