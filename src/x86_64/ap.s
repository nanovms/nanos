;;;  this needs to be placed on a 4k boundary in the first megabyte of the address space
;;;  https://wiki.osdev.org/Entering_Long_Mode_Directly

        bits 16
        align 4096
        %define CODE_SEG     0x0008 
        %define DATA_SEG     0x0010

        extern AP_BOOT_PAGE
        extern ap_start
        extern ap_stack
        extern ap_lock
global apinit

        %include "../../platform/pc/boot/longmode.inc"

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
        lidt [ap_idt_pointer]
        mov rbx, $1
        ; we serialize the processors coming in so they can temporarily use 
        ; the same stack
spin:   lock xchg [ap_lock], rbx
        test rbx, 1
        jne spin
        mov rsp, [ap_stack]
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
