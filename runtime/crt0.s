        global _start
        extern init_service
global frame

        ;; frame size is 136..? 
frame:  dq 0
        
extern common_handler
interrupt_common:
        push rax
        mov rax, frame
        mov rax, [rax]
        mov [rax+8], rbx
        mov [rax+16], rcx
        mov [rax+24], rdx
        mov [rax+32], rbp
        mov [rax+40], rsp   ;ehh, off by 16 plus the stack frame
        mov [rax+48], rsi
        mov [rax+56], rdi
        mov [rax+64], r8
        mov [rax+72], r9
        mov [rax+80], r10
        mov [rax+88], r11
        mov [rax+96], r12
        mov [rax+104], r13
        mov [rax+112], r14
        mov [rax+120], r15
        pop rbx            ; actually eax
        mov [rax], rbx
        pop rbx            ; vector
        mov [rax+128], rbx
        ;; assuming no error code
        pop rbx            ; eip
        mov [rax+136], rbx
        pop rbx            ; discard cs
        pop rbx            ; rflags
        mov [rax+144], rbx
        pop rbx            ; rflags
        mov [rax+40], rbx  ; rsp
                           ; ss plus padding at the top  
        call common_handler
;;;  rflags
;;;  rip

frame_return:
        mov rax, [frame]
        mov rbx, [frame+8]
        mov rcx, [frame+16]
        mov rdx, [frame+24]
        mov rbp, [frame+32]
        mov rsp, [frame+40]
        mov rsi, [frame+48]
        mov rdi, [frame+56]
        mov r8, [frame+64]
        mov r9, [frame+72]
        mov r10, [frame+80]
        mov r11, [frame+88]
        mov r12, [frame+96]
        mov r13, [frame+104]
        mov r14, [frame+112]
        mov r15, [frame+120]
        iretq
        ;;  intr in 128
;;;  rflags
;;;  rip

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
        push dword i
        jmp interrupt_common
        %assign i i+1        
        %endrep

_start:
        call init_service
;; can we shut down qemu from here?
        hlt




