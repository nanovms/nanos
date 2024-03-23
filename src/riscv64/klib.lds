OUTPUT_FORMAT("elf64-littleriscv")

ENTRY(init)

PHDRS
{
        text PT_LOAD FLAGS(5);          /* R E */
        rodata PT_LOAD FLAGS(4);        /* R */
        data PT_LOAD FLAGS(6);          /* RW */
}

SECTIONS
{
        . = SIZEOF_HEADERS;
        .text : { *(.text) *(.text.*) } :text
        . = ALIGN(4096);
        .rodata : { *(.rodata) *(.rodata.*) } :rodata

        . = ALIGN(4096);
        .data : { *(.data) *(.data.*) } :data
        .bss : { *(.bss) *(.bss.*) } :data

        /DISCARD/ : { *(.interp) }
}
