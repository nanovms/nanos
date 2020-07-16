display/i $pc
target remote :1234
b *0x00080a6
c
disconnect
set architecture i386:x86-64:intel
target remote :1234
