ROOT = ..
all:stage3
CC = cc
INCLUDES = -include stage3.h

include $(ROOT)/runtime/Makefile
include $(ROOT)/x86_64/Makefile
include $(ROOT)/virtio/Makefile
include $(ROOT)/net/Makefile
include $(ROOT)/gdb/Makefile
include $(ROOT)/unix/Makefile
include $(ROOT)/tfs/Makefile

INCLUDES += -I.
#refactor
RUNTIME_EXTRA = rtrie.o pqueue.o timer.o kvm_platform.o

stage3: $(NETOBJ) stage3.o $(RUNTIME) $(RUNTIME_EXTRA) $(VIRTIO) $(VIRTIO_NET) $(X86_64_OBJ) $(SYSCALL_INTERFACE) $(GDB) $(UNIX) $(TFS)
	ld -n -e_start -T linker_script -nostdlib $^ -o stage3

.c.o:
	$(CC) $(INCLUDES) -g -O -nostdinc -fno-stack-protector $< -c

# fix the frame nasm clean
clean:
	rm -f *.o *~ stage3 frame_nasm.h

