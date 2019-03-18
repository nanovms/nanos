include ../../config.mk
include ../../common.mk

OUT = $(ROOT)/output/test/runtime

CFLAGS = -g \
	 -fno-omit-frame-pointer \
	 -DHOST_BUILD \
	 -DENABLE_MSG_DEBUG \
	 $(includes)
CFLAGS+= $(CFLAG_WARNINGS) \
	-std=gnu11 \
         -Wformat
ifeq ($(UNAME_s),Darwin)
CFLAGS += -target x86_64-elf --sysroot $(TARGET_ROOT)
HOSTLD = x86_64-elf-ld
HOSTLDFLAGS += --sysroot=$(TARGET_ROOT)
OBJS_BEGIN=	$(OBJS_CRTBEGIN)
OBJS_END=	$(OBJS_CRTEND)
GO_ENV=		GOOS=linux GOARCH=amd64
endif

all: fst hw hws hwg getdents udploop web webg webgs webs getrandom mkdir time \
	 pipe write creat sendfile

fst: $(FST)

hw: $(HW)

hws: $(HWS)

hwg: $(HWG)

getdents: $(GETDENTS)

mkdir: $(MKDIR)

udploop: $(UDPLOOP)

getrandom: $(GETRANDOM)

creat: $(CREAT)

time: $(TIME)

web: $(WEB)

webs: $(WEBS)

webg: $(WEBG)

webgs: $(WEBGS)

pipe: $(PIPE)

write: $(WRITE)

sendfile: $(SENDFILE)

includes := \
	-I$(SRC)/runtime \
	-I$(SRC)/unix \
	-I$(SRC)/unix_process \
	-I$(SRC)/x86_64

hw-srcs := \
	$(ROOT)/test/runtime/hw.c

hw-objs = $(call srcs-to-objs,$(ROOT),$(OUT),hw)

ifeq ($(UNAME_s),Darwin)
$(HW): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(HW): OBJS_END=$(OBJS_CRTEND_D)
endif
$(HW): $(hw-objs)
	$(call cmd,host-prog)

hws-objs := $(hw-objs)

$(HWS): HOSTLDFLAGS += -static
$(HWS): $(hw-objs)
	$(call cmd,host-prog)

getdents-srcs := \
	$(ROOT)/test/runtime/getdents.c

getdents-objs = $(call srcs-to-objs,$(ROOT),$(OUT),getdents)

$(GETDENTS): HOSTLDFLAGS += -static
$(GETDENTS): $(getdents-objs)
	$(call cmd,host-prog)

write-srcs := \
	$(ROOT)/test/runtime/write.c

write-objs = $(call srcs-to-objs,$(ROOT),$(OUT),write)

$(WRITE): HOSTLDFLAGS += -static
$(WRITE): $(write-objs)
	$(call cmd,host-prog)

sendfile-srcs := \
	$(ROOT)/test/runtime/sendfile.c

sendfile-objs = $(call srcs-to-objs,$(ROOT),$(OUT),sendfile)

$(SENDFILE): HOSTLDFLAGS += -static
$(SENDFILE): $(sendfile-objs)
	$(call cmd,host-prog)

mkdir-srcs := \
	$(ROOT)/test/runtime/mkdir.c

mkdir-objs = $(call srcs-to-objs,$(ROOT),$(OUT),mkdir)

$(MKDIR): HOSTLDFLAGS += -static
$(MKDIR): $(mkdir-objs)
	$(call cmd,host-prog)

udploop-srcs := \
	$(ROOT)/test/runtime/udploop.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \
	$(SRC)/unix_process/http.c \
	$(SRC)/unix_process/socket_user.c \
	$(SRC)/unix_process/tiny_heap.c \
	$(SRC)/unix/path.c \
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
	$(SRC)/runtime/range.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/sha256.c \
	$(SRC)/runtime/signature.c \
	$(SRC)/runtime/string.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/tuple_parser.c \
	$(SRC)/runtime/tuple.c \

udploop-objs = $(call srcs-to-objs,$(ROOT),$(OUT),udploop)

$(UDPLOOP): HOSTLDFLAGS += -static
$(UDPLOOP): $(udploop-objs)
	$(call cmd,host-prog)

getrandom-srcs := \
	$(ROOT)/test/runtime/getrandom.c

getrandom-objs = $(call srcs-to-objs,$(ROOT),$(OUT),getrandom)

$(GETRANDOM): HOSTLDFLAGS += -static
$(GETRANDOM): EXTRA_HOSTLDFLAGS = -lm
$(GETRANDOM): $(getrandom-objs)
	$(call cmd,host-prog)

creat-srcs := \
	$(ROOT)/test/runtime/creat.c

creat-objs = $(call srcs-to-objs,$(ROOT),$(OUT),creat)

$(CREAT): HOSTLDFLAGS += -static
$(CREAT): $(creat-objs)
	$(call cmd,host-prog)

time-srcs := \
	$(ROOT)/test/runtime/time.c

time-objs = $(call srcs-to-objs,$(ROOT),$(OUT),time)

$(TIME): HOSTLDFLAGS += -static
$(TIME): $(time-objs)
	$(call cmd,host-prog)

pipe-srcs := \
	$(ROOT)/test/runtime/pipe.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix/path.c \
	$(SRC)/runtime/bitmap.c \
	$(SRC)/runtime/buffer.c \
	$(SRC)/runtime/extra_prints.c \
	$(SRC)/runtime/format.c \
	$(SRC)/runtime/random.c \
	$(SRC)/runtime/runtime_init.c \
	$(SRC)/runtime/string.c \
	$(SRC)/runtime/symbol.c \
	$(SRC)/runtime/table.c \
	$(SRC)/runtime/tuple_parser.c \
	$(SRC)/runtime/tuple.c \
	$(SRC)/runtime/timer.c \
	$(SRC)/runtime/pqueue.c \
	$(SRC)/runtime/heap/id.c \
	$(SRC)/runtime/heap/freelist.c \
	$(SRC)/runtime/heap/debug_heap.c \
	$(SRC)/runtime/heap/objcache.c \
	$(SRC)/runtime/heap/mcache.c \

pipe-objs = $(call srcs-to-objs,$(ROOT),$(OUT),pipe)

$(PIPE): HOSTLDFLAGS += -static
$(PIPE): EXTRA_HOSTLDFLAGS = -lm -lpthread
$(PIPE): $(pipe-objs)
	$(call cmd,host-prog)

web-srcs := \
	$(ROOT)/test/runtime/web.c \
	$(SRC)/unix_process/unix_process_runtime.c \
	$(SRC)/unix_process/mmap_heap.c \
	$(SRC)/unix_process/http.c \
	$(SRC)/unix_process/socket_user.c \
	$(SRC)/unix_process/tiny_heap.c \
	$(SRC)/unix/path.c \
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
	$(SRC)/runtime/range.c \
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

ifeq ($(UNAME_s),Darwin)
$(WEB): OBJS_BEGIN=$(OBJS_CRTBEGIN_D)
$(WEB): OBJS_END=$(OBJS_CRTEND_D)
endif
$(WEB): $(web-objs)
	$(call cmd,host-prog)

webs-objs := $(web-objs)

$(WEBS): HOSTLDFLAGS += -static
$(WEBS): $(web-objs)
	$(call cmd,host-prog)

$(WEBGS): webg.go
	@ mkdir -p $(dir $@)
	@ echo "GO	$@"
	$(Q) CGO_ENABLED=0 $(GO_ENV) $(GO) build -a -ldflags '-extldflags "-static"' -o $@ $^

$(hw-objs) $(web-objs) $(udploop-objs): $(CLOSURE_TMPL)

clean-objs = $(hw-objs) $(web-objs) $(FST) $(HW) $(HWG) $(HWS) $(WEB) $(WEBG) \
	$(WEBGS) $(WEBS) $(CLOSURE_TMPL) $(getdents-objs) $(GETDENTS) \
	$(getrandom-objs) $(GETRANDOM) $(udploop-objs) $(UDPLOOP) \
	$(mkdir-objs) $(MKDIR) $(time-objs) $(TIME) $(write-objs) $(WRITE) \
	$(pipe-objs) $(PIPE) $(creat-objs) $(CREAT) $(sendfile-objs) $(SENDFILE)

clean: default-clean

.PHONY: fst hw hwg hws web webg webgs webs getdents getrandom time udploop mkdir \
	pipe write creat sendfile

include ../../rules.mk
