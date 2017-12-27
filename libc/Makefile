all: libc.a
MUSL = $(ROOT)/libc/musl
ARCH = x86_64

INCLUDES += -I$(MUSL)/src/internal -I$(MUSL)/include -I. -I$(MUSL)/arch/$(ARCH) -I$(MUSL)/arch/generic
SRC_DIRS = $(MUSL)/src/string $(MUSL)/src/stdlib
VPATH += $(SRC_DIRS)

EXCLUDE = strsignal.o

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
	mkdir bits
	sed -f $(MUSL)/tools/mkalltypes.sed $(ALLTYPES_IN) $(GENERIC_IN) > $@

musl: force
	git clone git://git.musl-libc.org/musl
	cd musl ; git checkout v1.1.18

%.o: %.s
	cc $< -c

%.o: %.c bits/alltypes.h
	cc $< -nostdinc $(INCLUDES) -c

libc.a: $(ALL_OBJS)
	echo  $(ALL_OBJS)
	ar r libc.a $(ALL_OBJS) ; ranlib libc.a

force:

clean:
	rm -rf *.o *~ libc.a bits
