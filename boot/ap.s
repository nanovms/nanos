;;;  this needs to be plaved on a 4k boundary in the first megabyte of the address space
;;;  https://wiki.osdev.org/Entering_Long_Mode_Directly

        bits 16
        align 4096
        %define CODE_SEG     0x0008 
        %define DATA_SEG     0x0010

        extern ap_start
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
        or eax, 0x00000900  ; Set the LME bit and nxe
        wrmsr
        mov ebx, cr0        ; Activate long mode -
        or ebx,0x80000001   ; - by enabling paging and protection simultaneously.
        ;; xxx clear the em bit
        mov cr0, ebx
        o32 lgdt [ap_gdt_pointer-apinit]
        ; get this value out of the cs register and do an indirect jump
        jmp CODE_SEG:(LongMode-apinit + 0x8000)
bits 64
LongMode:
        ;; should get the data segment from a define..why are we setting these up even?
        mov ax, 0x10
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax
        mov ss, ax
        lidt [ap_idt_pointer]
        mov rbx, $1
        ; we serialize the processors coming in so they can temporarily use 
        ; the same stack
spin:   lock xchg [ap_lock], rbx
        test rbx, 1
        jne spin
        mov rsp,[ap_stack]
        mov rax, ap_start
        jmp rax  ;; its generating a relative jump...but we moved this code..alot

global ap_gdt_pointer        
ap_gdt_pointer:
        dw 0      ; 16-bit Size (Limit) of GDT.
        dd 0      ; 32-bit Base Address of GDT. (CPU will zero extend to 64-bit)
        dd 0      ; spill for 64 bit gdt write
        
global ap_idt_pointer        
ap_idt_pointer:
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
global ap_stack
ap_stack:
        dq 0
        align 8
global ap_lock
ap_lock:
        dq 0        
        
global apinit_end
        
apinit_end:    
