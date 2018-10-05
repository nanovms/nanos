include $(ROOT)/runtime/Makefile

INCLUDES += -DUNIX_PROCESS

VPATH += $(ROOT)/unix_process
INCLUDES +=  -I$(ROOT)/unix_process
UNIXRUNTIME = $(RUNTIME) unix_process_runtime.o mmap_heap.o http.o socket_user.o tiny_heap.o poll_user.o select_user.o

INCLUDES += -I$(ROOT)/x86_64 
