OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
SECTIONS
{
    . = 0;
    IMAGE_BASE = .;
    .hash : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }

    . = ALIGN(4096);
    .eh_frame : {
        *(.eh_frame)
    }

    . = ALIGN(4096);
    .text : {
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

    . = ALIGN(4096);
    .rela : {
        *(.rela.data*)
        *(.rela.got)
        *(.rela.stab)
    }

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
