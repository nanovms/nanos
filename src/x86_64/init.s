default rel

section .start

;;;  this needs to be placed on a 4k boundary in the first megabyte of the address space
;;;  https://wiki.osdev.org/Entering_Long_Mode_Directly

        bits 16
        align 4096
        %define CODE_SEG     0x0008
        %define DATA_SEG     0x0010

        %define AP_BOOT_PAGE 0x0
        extern ap_start
        extern ap_stack
        extern ap_lock
global apinit

        %include "../../platform/pc/boot/longmode.inc"

boot_base:

apinit:
        mov ax, cs
        mov ds, ax
        PREPARE_LONG_MODE eax
        mov edx, [ap_pagetable-apinit]
        mov cr3, edx        ; page table (relocated copy)

        ENTER_LONG_MODE ebx

        ;; load from relocated copy of gdt pointer
        o32 lgdt [AP_BOOT_PAGE + ap_gdt.Pointer - apinit]
        ; get this value out of the cs register and do an indirect jump
        jmp CODE_SEG:(AP_BOOT_PAGE + LongMode - apinit)
bits 64
LongMode:
        ;; should get the data segment from a define..why are we setting these up even?
        mov ax, 0x10
        mov ds, ax
        mov es, ax
        mov ss, ax
        xor ax, ax
        mov fs, ax
        mov gs, ax
        mov rax, ap_idt_pointer
        lidt [rax]
        mov rbx, $1
        ; we serialize the processors coming in so they can temporarily use
        ; the same stack
        mov rax, ap_lock
spin:   lock xchg [rax], rbx
        test rbx, 1
        jne spin
        mov rax, ap_stack
        mov rsp, [rax]
        mov rax, ap_start
        jmp rax   ; avoid relative jump as this code is repositioned

%include "segment.inc"

;; Temporary GDT (64-bit)
align 16
ap_gdt:
        .Null: equ $ - ap_gdt
        dd 0
        dd 0
        .Code: equ $ - ap_gdt
        dd 0
        dd KERN_CODE_SEG_DESC
        .Data: equ $ - ap_gdt
        dd 0
        dd KERN_DATA_SEG_DESC
        .UserCode: equ $ - ap_gdt
        dd 0
        dd 0
        .UserData: equ $ - ap_gdt
        dd 0
        dd USER_DATA_SEG_DESC
        .UserCode64: equ $ - ap_gdt
        dd 0
        dd USER_CODE_SEG_DESC
        .Pointer:
        dw $ - ap_gdt - 1                   ; Limit.
        dq (AP_BOOT_PAGE + ap_gdt - apinit) ; 64 bit Base.

;; These are relocated, but only after being filled in by start_cpu
global ap_pagetable
ap_pagetable:
        dq 0

global apinit_end
apinit_end:

;; Not relocated

global ap_idt_pointer
ap_idt_pointer:
        dw 0      ; 16-bit Size (Limit) of GDT.
        dd 0      ; 32-bit Base Address of GDT. (CPU will zero extend to 64-bit)
        dd 0      ; spill for 64 bit gdt write

%define PVH_START_BASE 0x00200000

global pvh_start32
extern pvh_start

bits 32
pvh_start32:
        PREPARE_LONG_MODE eax
        ; set up minimal mapping to be able to run in 64-bit mode, carving page
        ; tables from the top of the first 1MB of memory (which will not be
        ; included in the physical memory regions)
        mov eax, 0x100000 - 0x1000 ; PML4
        mov edi, eax
        call pvh_zero_page
        ; PDPT
        mov ecx, eax
        sub ecx, 0x1000
        mov edi, ecx
        call pvh_zero_page
        mov [eax], ecx
        or dword [eax], 0x7
        mov dword [eax + 4], 0
        ; PDT
        mov edx, ecx
        sub edx, 0x1000
        mov edi, edx
        call pvh_zero_page
        mov [ecx], edx
        or dword [ecx], 0x7
        mov dword [ecx + 4], 0
        ; map start info data (whose address is in the ebx register)
        mov ecx, ebx
        and ecx, 0xffe00000
        mov esi, ecx
        shr esi, 18
        mov dword [edx + esi], ecx
        or dword [edx + esi], 0x83
        mov dword [edx + esi + 4], 0
        ; set stack pointer to INITIAL_MAP_SIZE, and map stack memory
        mov esp, 0xa000
        mov dword [edx], 0x83
        mov dword [edx + 4], 0
        ; map kernel code
        mov dword [edx + 8], 0x200000 | 0x83
        mov dword [edx + 12], 0
        mov cr3, eax
        ENTER_LONG_MODE eax
        lgdt [PVH_START_BASE + pvh_gdt.Pointer - boot_base]
        jmp pvh_gdt.Code:(PVH_START_BASE + pvh_long_mode - boot_base)

pvh_zero_page:
        mov esi, edi
        add esi, 0x1000
.loop   mov dword [edi], 0x00000000
        add edi, 4
        cmp edi, esi
        jne .loop
        ret

bits 64
pvh_long_mode:
        mov edi, ebx ; retrieve start info address from ebx register
        jmp pvh_start

align 16
pvh_gdt:
        .Null: equ $ - pvh_gdt
        dd 0
        dd 0
        .Code: equ $ - pvh_gdt
        dd 0
        dd KERN_CODE_SEG_DESC
        .Data: equ $ - pvh_gdt
        dd 0
        dd KERN_DATA_SEG_DESC
        .UserCode: equ $ - pvh_gdt
        dd 0
        dd 0
        .UserData: equ $ - pvh_gdt
        dd 0
        dd USER_DATA_SEG_DESC
        .UserCode64: equ $ - pvh_gdt
        dd 0
        dd USER_CODE_SEG_DESC
        .Pointer:
        dw $ - pvh_gdt - 1  ; Limit
        dq (pvh_gdt)        ; 64 bit Base
