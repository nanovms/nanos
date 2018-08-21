VPATH += $(ROOT)/x86_64

FRAME := $(ROOT)/x86_64/frame.h

frame_nasm.h: $(FRAME)
	sed -e "s/#/%/" < $(FRAME) > frame_nasm.h

crt0.o: crt0.s frame_nasm.h
	nasm -felf64 $< -o $@

INCLUDES += -I$(ROOT)/x86_64
X86_64_OBJ= pci.o serial.o page.o interrupt.o clock.o crt0.o service.o elf.o breakpoint.o\
            queue.o backed_heap.o fragment.o synth.o symtab.o


