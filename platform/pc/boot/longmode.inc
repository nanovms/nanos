    %define CR4_PAE (1<<5)
    %define CR4_PGE (1<<7)
    %define CR4_OSFXSR (1<<9)
    %define CR4_OSXMMEXCPT (1<<10)
    %define CR4_OSXSAVE (1<<18)

    %macro PREPARE_LONG_MODE 1
    mov %1, CR4_PAE | CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT ;| CR4_OSXSAVE
    mov cr4, %1

    mov ecx, 0xC0000080 ; Read from the EFER MSR.
    rdmsr
    or %1, 0x00000900  ; Set the LME bit and nxe
    wrmsr
    %endmacro

    %macro ENTER_LONG_MODE 1
    mov %1, cr0        ; Activate long mode -
    or %1, 0x80000001  ; - by enabling paging and protection simultaneously.
    and %1, ~0x4       ; clear EM
    or %1, 0x2         ; set MP
    mov cr0, %1
    %endmacro

