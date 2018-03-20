ROOT = ..
all:stage3
include $(ROOT)/runtime/Makefile
include $(ROOT)/x86_64/Makefile
include $(ROOT)/virtio/Makefile
include $(ROOT)/net/Makefile
INCLUDES += -I.

stage3: stage3.o $(RUNTIME) $(VIRTIO) $(NETOBJ) $(VIRTIO_NET) $(X86_64_OBJ) $(SYSCALL_INTERFACE) $(GDBSTUB)
	ld -n -e_start -T linker_script -nostdlib $^ -o stage3

.c.o:
	cc $(INCLUDES) -O -nostdinc -fno-stack-protector $< -c

clean:
	rm -f *.o *~ stage3

