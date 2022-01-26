OUTPUT_FORMAT("elf64-littleaarch64", "elf64-littleaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)
SECTIONS
{
    . = 0;
    .text : {
        *(.text.head)
        *(.text)
        *(.text.*)
        *(.gnu.linkonce.t.*)
    }

    . = ALIGN(4096);
    .reloc : {
        *(.reloc)
    }

    . = ALIGN(4096);
    .data : {
        _data = .;
        *(.rodata*)
        *(.got.plt)
        *(.got)
        *(.data*)
        *(.sdata)
        *(.sbss)
        *(.scommon)
        *(.dynbss)
        *(.bss)
        *(COMMON)
        *(.rel.local)
    }
    .note.gnu.build-id : { *(.note.gnu.build-id) }

    . = ALIGN(4096);
    .dynamic  : { *(.dynamic) }

    _edata = .;
    _data_size = . - _data;

    . = ALIGN(4096);
    .dynsym   : { *(.dynsym) }

    . = ALIGN(4096);
    .dynstr   : { *(.dynstr) }

    . = ALIGN(4096);
    .ignored.reloc : {
        *(.rela.reloc)
        *(.eh_frame)
        *(.note.GNU-stack)
    }
    .comment 0 : { *(.comment) }
}
