        global _start
        extern init_service
        
        ;; frame size is 136..? 
extern frame


;;;  correlation to allow us to get back in the relative, virtual, addresses
;;;  of data after the interrupt has tracked us onto physical
;;;  there should be a better place to stash this
;;;  frame might be stashable in a segment register
absolution equ 0x7de8
        
extern common_handler
interrupt_common:
        push rax
        mov rax, [frame]
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
        pop rbx            ; rsp?
        mov [rax+40], rbx  ; 
                           ; ss plus padding at the top  
        call common_handler


frame_return:
        mov rax, [frame]
        mov rbx, [rax+8]
        mov rcx, [rax+16]
        mov rdx, [rax+24]
        mov rbp, [rax+32]
        mov rsi, [rax+48]
        mov rdi, [rax+56]
        mov r8, [rax+64]
        mov r9, [rax+72]
        mov r10, [rax+80]
        mov r11, [rax+88]
        mov r12, [rax+96]
        mov r13, [rax+104]
        mov r14, [rax+112]
        mov r15, [rax+120]
        push qword 0x10     ; ss
        push qword [rax+40]      ; rsp
        push qword [rax+144]   ; rflags
        push qword 0x08   ; cs        
        push qword [rax+136]   ; rip
        mov rax, [rax]
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
        jmp [absolution]
        %assign i i+1        
        %endrep

_start:
        mov rax, qword absolution 
        mov qword [rax], interrupt_common
        call init_service
;; can we shut down qemu from here?
        hlt




