set architecture i386:x86-64

macro define offsetof(t, f) (size_t)&((t *)0)->f
macro define container_of(p, t, f) (t *)((void *)p - offsetof(t, f))

source tools/nanos_gdb.py
display/i $pc
symbol-file ./output/platform/pc/bin/kernel.elf
target remote :1234

