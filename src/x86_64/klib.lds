OUTPUT_FORMAT("elf64-x86-64")

ENTRY(init)

SECTIONS
{
        . = SIZEOF_HEADERS;
        .text : { *(.text)}
        .rodata : { *(.rodata)}

        .data ALIGN(4096) : { *(.data) *(.data.*) }
        .bss ALIGN(32): { *(.bss) *(.bss.*) }

        /DISCARD/ : { *(.interp) }
}
