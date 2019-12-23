;;;  this needs to be plaved on a 4k boundary in the first megabyte of the address space
;;;  https://wiki.osdev.org/Entering_Long_Mode_Directly

        bits 16
        align 4096
        %define CODE_SEG     0x0008 
        %define DATA_SEG     0x0010
        
global apinit

apinit:
        mov ax, cs
        mov ds, ax
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
        o32 lgdt [ap_gdt_pointer-apinit]
; pass this                      
        jmp CODE_SEG:(LongMode-apinit + 0x8000)
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
        dd 0      ; spill for 64 bit gdt write
        
global ap_pagetable
ap_pagetable:    
        dq 0
        global start_vector
global ap_start_vector
ap_start_vector:
        dq 0
        
global apinit_end
        
apinit_end:    
