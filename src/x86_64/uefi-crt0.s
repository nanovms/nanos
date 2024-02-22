bits 64

%include "longmode.inc"

extern IMAGE_BASE
extern _DYNAMIC ; linker symbol with the start address of the .dynamic section
extern elf_dyn_relocate
extern efi_main

section .text

global _start
_start:
    sub rsp, 8
    push rcx    ; image handle
    push rdx    ; system table

    lea rdi, [rel IMAGE_BASE]
    mov rsi, rdi
    lea rdx, [rel _DYNAMIC]
    call elf_dyn_relocate

    mov ecx, MSR_EFER
    rdmsr
    or eax, EFER_NXE
    wrmsr

    pop rsi    ; system table
    pop rdi    ; image handle
    call efi_main

    add rsp, 8
    ret

global read_msr
read_msr:
    mov rcx, rdi
    mov rax, 0
    rdmsr
    shl rdx, 0x20
    or rax, rdx
    ret

global write_msr
write_msr:
    mov rcx, rdi
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 0x20
    wrmsr
    ret

;; The .reloc section contains the fixup table; it must be present and non-emtpy
;; even if there are no fixups to be applied
section .reloc

align 4
;; Dummy fixup block, with no fixups
    dd 0    ; page RVA (dummy)
    dd 8    ; block size
