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

        %define CR4_PAE (1<<5)
        %define CR4_PGE (1<<7)
        %define CR4_OSFXSR (1<<9)
        %define CR4_OSXMMEXCPT (1<<10)        
        %define CR4_OSXSAVE (1<<18)                
        
apinit:
        mov ax, cs
        mov ds, ax
        mov eax, CR4_PAE | CR4_PGE | CR4_OSXSAVE 
        mov cr4, eax
        mov edx, [ap_pagetable-apinit]
        mov cr3, edx        ; page table (relocated copy)
        mov ecx, 0xC0000080 ; Read from the EFER MSR.
        rdmsr
        or eax, 0x00000900  ; Set the LME bit and nxe
        wrmsr

        ;; XXX this should be unified with stage2 centry
        mov ebx, cr0        ; Activate long mode -
        or ebx,0x80000001   ; - by enabling paging and protection simultaneously.
        and ebx, ~0x4       ; clear EM
        or ebx, 0x2         ; set MP
        mov cr0, ebx
        mov ebx, cr4
        or ebx, CR4_OSFXSR | CR4_OSXMMEXCPT
        mov cr4, ebx

        ;; load from relocated copy of gdt pointer
        o32 lgdt [AP_BOOT_PAGE + ap_gdt_pointer - apinit]
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

;; These are relocated, but only after being filled in by start_cpu
global ap_gdt_pointer        
ap_gdt_pointer:
        dw 0      ; 16-bit Size (Limit) of GDT.
        dd 0      ; 32-bit Base Address of GDT. (CPU will zero extend to 64-bit)
        dd 0      ; spill for 64 bit gdt write
        
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
