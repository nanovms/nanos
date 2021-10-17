set architecture i386:x86-64

source tools/nanos_gdb.py
display/i $pc
symbol-file ./output/platform/pc/bin/kernel.elf
target remote :1234

