        global _start
        extern init_service

extern common_handler
interrupt_common:
        ;;;  save context indirect
;;;  use fs or gs to point to context?
        call common_handler
        iretq
        
        interrupts equ 0x30

global interrupt_size
interrupt_size:
        dd interrupts
        
        global interrupt0
        global interrupt1
vectors:        
        %assign i 0                
        %rep interrupts
        interrupt %+ i:
        mov al, i
        mov dx, 0x3f8
        out dx, al
        push i
        jmp interrupt_common
        %assign i i+1        
        %endrep

_start:
        call init_service
;; can we shut down qemu from here?
        hlt




