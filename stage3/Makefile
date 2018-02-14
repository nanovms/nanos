ROOT = ..
all:stage3
include $(ROOT)/runtime/Makefile
include $(ROOT)/virtio/Makefile
INCLUDES += -I.

stage3: stage3.o $(STANDALONE) $(VIRTIO)
	ld -n -e_start -T linker_script -nostdlib $^ -o stage3

.c.o:
	cc $(INCLUDES) -nostdinc -fno-stack-protector $< -c

clean:
	rm -f *.o *~ stage3

