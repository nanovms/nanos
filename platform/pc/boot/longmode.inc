    %define CR0_PE (1<<0)
    %define CR0_MP (1<<1)
    %define CR0_EM (1<<2)
    %define CR0_PG (1<<31)

    %define CR4_PAE (1<<5)
    %define CR4_PGE (1<<7)
    %define CR4_OSFXSR (1<<9)
    %define CR4_OSXMMEXCPT (1<<10)
    %define CR4_OSXSAVE (1<<18)

    %define MSR_EFER 0xC0000080
    %define EFER_LME (1<<8)
    %define EFER_NXE (1<<11)

    %macro PREPARE_LONG_MODE 1
    mov %1, CR4_PAE | CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT ;| CR4_OSXSAVE
    mov cr4, %1

    mov ecx, MSR_EFER ; Read from the EFER MSR.
    rdmsr
    or %1, EFER_LME | EFER_NXE  ; Set the LME bit and nxe
    wrmsr
    %endmacro

    %macro ENTER_LONG_MODE 1
    mov %1, cr0        ; Activate long mode -
    or %1, CR0_PG | CR0_PE  ; - by enabling paging and protection simultaneously.
    and %1, ~CR0_EM       ; clear EM
    or %1, CR0_MP         ; set MP
    mov cr0, %1
    %endmacro

