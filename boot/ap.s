;;; ; xxx xxx - this needs to be on a page boundary in the first megabyte of the address space!
;;;  https://wiki.osdev.org/Entering_Long_Mode_Directly
        
;;;  ok. we'd love to just share symbols between stage3 and this guy. but the fact that
;;; this starts out in real mode really throws the linker for the loop
;;; so we put an offset at the end of the page to point to a config region
;;; within which to place the gdt and cr3 data from the primary cpu

        bits 16
        align 4096
        %define CODE_SEG     0x0008 
        %define DATA_SEG     0x0010
        
global apinit

apinit:
        mov ax, 0x0
        mov ds, ax
        mov ax, 1
        mov [apinit_end-apinit], ax
        mov eax, 10100000b  ; Set the PAE and PGE bit.
        mov cr4, eax
        mov edx, [ap_pagetable-apinit]
        mov cr3, edx            ; page table
        mov ecx, 0xC0000080 ; Read from the EFER MSR.
        rdmsr
        or eax, 0x00000100  ; Set the LME bit.
        wrmsr
        mov ebx, cr0        ; Activate long mode -
        or ebx,0x80000001   ; - by enabling paging and protection simultaneously.
        mov cr0, ebx
        lgdt [ap_gdt_pointer-apinit] 
        jmp CODE_SEG:(LongMode-apinit)
bits 64
LongMode:
        mov ax, 0x10
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax
        mov ss, ax
        mov rax,[ap_start_vector]
        jmp [rax]

global ap_gdt_pointer        
ap_gdt_pointer:
        dw 0      ; 16-bit Size (Limit) of GDT.
        dd 0      ; 32-bit Base Address of GDT. (CPU will zero extend to 64-bit)
        
global ap_pagetable
ap_pagetable:    
        dq 0
        global start_vector
global ap_start_vector
ap_start_vector:
        dq 0
        
global apinit_end
        
apinit_end:    
