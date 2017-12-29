all: libc.a
MUSL = $(ROOT)/libc/musl
ARCH = x86_64

INCLUDES += -I$(MUSL)/src/internal -I$(MUSL)/include -I$(MUSL)/arch/$(ARCH) -I$(MUSL)/arch/generic
SRC_DIRS = $(MUSL)/src/string $(MUSL)/src/stdlib $(MUSL)/src/stdio $(MUSL)/src/multibyte $(MUSL)/src/env $(MUSL)/src/internal
VPATH += $(SRC_DIRS)

EXCLUDE = strsignal.o __fdopen.o __fopen_rb_ca.o __lockfile.o __stdio_close.o __stdio_read.o __fclose_ca.o __overflow.o __stdio_exit.o __stdio_seek.o __stdout_write.o __stdio_write.o __string_read.o __toread.o __towrite.o __uflow.o pclose.o

# copied from the musl root build
BASE_GLOBS = $(addsuffix /*.c,$(SRC_DIRS))
ARCH_GLOBS = $(addsuffix /$(ARCH)/*.[csS],$(SRC_DIRS))
BASE_SRCS = $(sort $(wildcard $(BASE_GLOBS)))
ARCH_SRCS = $(sort $(wildcard $(ARCH_GLOBS)))
BASE_OBJS = $(patsubst $(srcdir)/%,%.o,$(basename $(BASE_SRCS)))
ARCH_OBJS = $(patsubst $(srcdir)/%,%.o,$(basename $(ARCH_SRCS)))
REPLACED_OBJS = $(sort $(subst /$(ARCH)/,/,$(ARCH_OBJS)))
MOST_OBJS = $(notdir $(filter-out $(REPLACED_OBJS), $(sort $(BASE_OBJS) $(ARCH_OBJS))))
ALL_OBJS = $(filter-out $(EXCLUDE), $(MOST_OBJS))

ALLTYPES_IN = $(MUSL)/arch/$(ARCH)/bits/alltypes.h.in
GENERIC_IN = $(MUSL)/include/alltypes.h.in
bits/alltypes.h: $(ALLTYPES_IN) $(GENERIC_IN) $(MUSL)/tools/mkalltypes.sed
	mkdir -p bits
	sed -f $(MUSL)/tools/mkalltypes.sed $(ALLTYPES_IN) $(GENERIC_IN) > $@

bits/syscall.h: internal/syscall.h
	mkdir -p bits
	cp $^ $@

musl: 
	git clone git://git.musl-libc.org/musl
	cd musl ; git checkout v1.1.18

%.o: %.s
	cc $< -c

%.o: %.c bits/alltypes.h bits/syscall.h
	cc $< -fno-stack-protector -nostdinc -I. $(INCLUDES) -c

libc.a: musl $(ALL_OBJS)
	ar r libc.a $(ALL_OBJS) ; ranlib libc.a

force:

clean:
	rm -rf *.o *~ libc.a 
