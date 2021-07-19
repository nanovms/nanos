set architecture i386:x86-64

source tools/nanos_gdb.py
display/i $pc
target remote :1234
symbol-file ./output/platform/pc/bin/kernel.elf

