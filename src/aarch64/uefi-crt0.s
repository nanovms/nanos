    .section .text.head
	.globl IMAGE_BASE
IMAGE_BASE:

/* PE/COFF header */

msdos_stub:
    .ascii "MZ"
    .skip 0x3a
    .long pe_signature - IMAGE_BASE // offset to the PE signature
pe_signature:
    .ascii "PE\0\0"
coff_header:
    .short 0xaa64                          // Machine
    .short 2                               // NumberOfSections
    .long 0                                // TimeDateStamp
    .long 0                                // PointerToSymbolTable
    .long 0                                // NumberOfSymbols
    .short section_table - optional_header // SizeOfOptionalHeader
    .short 0x0202                          // Characteristics
optional_header:
standard_fields:
    .short 0x20b              // Magic (PE32+ executable)
    .byte 0x02                // MajorLinkerVersion
    .byte 0x24                // MinorLinkerVersion
    .long _data - _start      // SizeOfCode
    .long _data_size          // SizeOfInitializedData
    .long 0                   // SizeOfUninitializedData
    .long _start - IMAGE_BASE // AddressOfEntryPoint
    .long _start - IMAGE_BASE // BaseOfCode
windows_specific_fields:
    .quad 0                   // ImageBase
    .long 0x1000              // SectionAlignment
    .long 0x1000              // FileAlignment
    .short 0                  // MajorOperatingSystemVersion
    .short 0                  // MinorOperatingSystemVersion
    .short 0                  // MajorImageVersion
    .short 0                  // MinorImageVersion
    .short 0                  // MajorSubsystemVersion
    .short 0                  // MinorSubsystemVersion
    .long 0                   // Win32VersionValue
    .long _edata - IMAGE_BASE // SizeOfImage
    .long _start - IMAGE_BASE // SizeOfHeaders
    .long 0                   // CheckSum
    .short 10                 // Subsystem (EFI application)
    .short 0                  // DllCharacteristics
    .quad 0                   // SizeOfStackReserve
    .quad 0                   // SizeOfStackCommit
    .quad 0                   // SizeOfHeapReserve
    .quad 0                   // SizeOfHeapCommit
    .long 0                   // LoaderFlags
    .long 0                   // NumberOfRvaAndSizes

section_table:

    .ascii ".text\0\0\0"      // Name
    .long _data - _start      // VirtualSize
    .long _start - IMAGE_BASE // VirtualAddress
    .long _data - _start      // SizeOfRawData
    .long _start - IMAGE_BASE // PointerToRawData
    .long 0                   // PointerToRelocations
    .long 0                   // PointerToLineNumbers
    .short 0                  // NumberOfRelocations
    .short 0                  // NumberOfLineNumbers
    .long 0x60000020          // Characteristics

    .ascii ".data\0\0\0"     // Name
    .long _data_size         // VirtualSize
    .long _data - IMAGE_BASE // VirtualAddress
    .long _data_size         // SizeOfRawData
    .long _data - IMAGE_BASE // PointerToRawData
    .long 0                  // PointerToRelocations
    .long 0                  // PointerToLineNumbers
    .short 0                 // NumberOfRelocations
    .short 0                 // NumberOfLineNumbers
    .long 0xc0000040         // Characteristics

    .align 8
_start:
    stp x29, x30, [sp, #-32]!
    stp x0, x1, [sp, #16]
    adr x0, IMAGE_BASE
    mov x1, x0
    adr x2, _DYNAMIC
    bl  elf_dyn_relocate
    ldp x0, x1, [sp, #16]
    bl  efi_main
    ldp x29, x30, [sp], #32
    ret
