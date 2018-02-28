        bits 32
        stack equ 0x700
        extern centry
        section .start
        

;; move the 32 bit segment setup to stage1
global _start
_start:
        xor edx, edx
        mov dl, 0x10 ; data32 from stage1
        mov ss, dx   
        mov ds, dx
        mov es, dx
        mov fs, dx
        mov gs, dx

        mov esp, stack
        mov ebp, stack        
        jmp centry

# try to fix the asm inline for this        
global disktarget
disktarget:     dd 0 
global diskcopy
diskcopy:
        push edi
        mov edi, [disktarget]
        mov dx, 0x1f0
        mov ecx, 256
        cld
        rep insd
        mov [disktarget], edi
        pop edi
        ret

global run64        
run64:

        mov eax, cr4     
        or eax, 1 << 5     ;  PAE
        or eax, 1 << 9     ;  osfxsr
        or eax, 1 << 10    ;  osxmmexcpt
        or eax, 1 << 18    ;  OSXSAVE
        mov cr4, eax  
        
        mov ecx, 0xC0000080 ; EFER MSR.
        
        rdmsr      
        or eax, 1 << 8      ; Set the LM-bit which is the 9th bit (bit 8).
        wrmsr

        pop edx                 ; return
        pop edx                 ; entry

        push eax
        push eax
        
        mov eax, cr0    
        or eax, 1 << 31 | 1 ; Set the PG-bit and the PM bit 
        and eax, ~4 ; clear the EM bit
        mov cr0, eax
        
        ;; 64 bit compatibility into the proper long mode
        lgdt [GDT64.Pointer]    ; Load the 64-bit global descriptor table.
        jmp GDT64.Code:setup64
align 16                        ; necessary?
GDT64:  ; Global Descriptor Table (64-bit).
        ;;  xxx - clean this up with a macro
        .Null: equ $ - GDT64 ; The null descriptor.
        dw 0  ; Limit (low).
        dw 0  ; Base (low).
        db 0  ; Base (middle)
        db 0  ; Access.
        db 0  ; Granularity.
        db 0  ; Base (high).
        .Code: equ $ - GDT64 ; The code descriptor.
        dw 0  ; Limit (low).
        dw 0  ; Base (low).
        db 0  ; Base (middle)    
        db 10011010b    ; Access (exec/read).
        db 00100000b    ; Granularity.
        db 0            ; Base (high).
        .Data: equ $ - GDT64 ; The data descriptor.
        dw 0         ; Limit (low).
        dw 0         ; Base (low).
        db 0         ; Base (middle)
        db 10010010b ; Access (read/write).
        db 00000000b ; Granularity.
        db 0         ; Base (high).
        .DataAgain: equ $ - GDT64 ; The data descriptor, a copy for sysret
        dw 0         ; Limit (low).
        dw 0         ; Base (low).
        db 0         ; Base (middle)
        db 10010010b ; Access (read/write).
        db 00000000b ; Granularity.
        db 0         ; Base (high).
        
        .Pointer:    ; The GDT-pointer.
        dw $ - GDT64 - 1    ; Limit.
        dw GDT64, 0         ; 64 bit Base.

        
setup64:
        mov ax, GDT64.Data 
        mov ds, ax     
        mov es, ax 
        mov fs, ax     
        mov gs, ax    
        mov ss, ax 
        jmp edx
