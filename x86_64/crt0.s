        ;;  this isn't c runtime zero, just some assembly stuff

%macro global_func 1
	global %1:function (%1.end - %1)
%endmacro
%macro global_data 1
	global %1:data (%1.end - %1)
%endmacro
        
global_func _start
        extern init_service
        
extern frame
%include "frame_nasm.h"
        
%define FS_MSR 0xc0000100
        
;;; optimize and merge - frame is loaded into rbx
global_func frame_enter
frame_enter:
        mov rax, [rbx+FRAME_FS*8]
        mov rcx, FS_MSR
        mov rdx, rax
        shr rdx, 0x20
        wrmsr ;; move fs, consider macro
        mov rdx, [rbx+FRAME_RDX*8]        
        mov rbp, [rbx+FRAME_RBP*8]
        mov rsi, [rbx+FRAME_RSI*8]
        mov rdi, [rbx+FRAME_RDI*8]
        mov r8,  [rbx+FRAME_R8*8]
        mov r9,  [rbx+FRAME_R9*8]
        mov r10, [rbx+FRAME_R10*8]
        mov r11, [rbx+FRAME_R11*8]
        mov r12, [rbx+FRAME_R12*8]
        mov r13, [rbx+FRAME_R13*8]
        mov r14, [rbx+FRAME_R14*8]
        mov r15, [rbx+FRAME_R15*8]
        mov rsp, [rbx+FRAME_RSP*8]                
        mov rax, [rbx+FRAME_RIP*8]
        push rax
        mov rax, [rbx+FRAME_FLAGS*8]        
        push rax        
        mov rax, [rbx+FRAME_RAX*8]
        mov rbx, [rbx+FRAME_RBX*8]                
        popf
        ret
.end:

;; syscall save and restore doesn't always have to be a full frame        
extern syscall
global_func syscall_enter
syscall_enter:   
        push rax
        mov rax, [frame]
        mov [rax+FRAME_RBX*8], rbx
        pop rbx
        mov [rax+FRAME_VECTOR*8], rbx
        mov [rax+FRAME_RDX*8], rdx
        mov [rax+FRAME_RBP*8], rbp
        mov [rax+FRAME_RSP*8], rsp
        mov [rax+FRAME_RSI*8], rsi
        mov [rax+FRAME_RDI*8], rdi
        mov [rax+FRAME_R8*8], r8
        mov [rax+FRAME_R9*8], r9
        mov [rax+FRAME_R10*8], r10
        mov [rax+FRAME_FLAGS*8], r11
        mov [rax+FRAME_R12*8], r12
        mov [rax+FRAME_R13*8], r13
        mov [rax+FRAME_R14*8], r14
        mov [rax+FRAME_R15*8], r15                               
        mov [rax+FRAME_RIP*8], rcx
        mov rax, syscall
        mov rax, [rax]
        call rax
        mov rbx, [frame]
        mov [rbx + FRAME_RAX], rax
        jmp frame_enter
.end:
        
extern common_handler
interrupt_common:
        push rax
        mov rax, [frame]
        mov [rax+FRAME_RBX*8], rbx
        mov [rax+FRAME_RCX*8], rcx
        mov [rax+FRAME_RDX*8], rdx
        mov [rax+FRAME_RSI*8], rsi
        mov [rax+FRAME_RDI*8], rdi
        mov [rax+FRAME_RBP*8], rbp
        mov [rax+FRAME_R8*8], r8
        mov [rax+FRAME_R9*8], r9
        mov [rax+FRAME_R10*8], r10
        mov [rax+FRAME_R11*8], r11
        mov [rax+FRAME_R12*8], r12
        mov [rax+FRAME_R13*8], r13
        mov [rax+FRAME_R14*8], r14
        mov [rax+FRAME_R15*8], r15
        pop rbx            ; eax
        mov [rax], rbx
        pop rbx            ; vector
        mov [rax+FRAME_VECTOR*8], rbx
        
        ;;  could avoid this branch with a different inter layout - write as different handler
        cmp rbx, 0xe
        je geterr
        cmp rbx, 0xd
        je geterr
        
getrip:
        pop rbx            ; eip
        mov [rax+FRAME_RIP*8], rbx
        pop rbx            ; discard cs
        pop rbx            ; rflags
        mov [rax+FRAME_FLAGS*8], rbx
        pop rbx            ; rsp?
        mov [rax+FRAME_RSP*8], rbx  
        pop rbx            ; ss         
        call common_handler

        ;; try to unify the interrupt and syscall paths
        ;; could always use iret?
global_func frame_return
frame_return:
        mov rbx, [frame]

        mov rax, [rbx+FRAME_FS*8]
        mov rcx, FS_MSR
        mov rdx, rax
        shr rdx, 0x20
        wrmsr ;; move fs, consider macro

        mov rax, rbx
        
        mov rbx, [rax+FRAME_RBX*8]
        mov rcx, [rax+FRAME_RCX*8]
        mov rdx, [rax+FRAME_RDX*8]
        mov rbp, [rax+FRAME_RBP*8]
        mov rsi, [rax+FRAME_RSI*8]
        mov rdi, [rax+FRAME_RDI*8]
        mov r8, [rax+FRAME_R8*8]
        mov r9, [rax+FRAME_R9*8]
        mov r10, [rax+FRAME_R10*8]
        mov r11, [rax+FRAME_R11*8]
        mov r12, [rax+FRAME_R12*8]
        mov r13, [rax+FRAME_R13*8]
        mov r14, [rax+FRAME_R14*8]
        mov r15, [rax+FRAME_R15*8]
        push qword 0x10     ; ss - should be 0x10? pp 293
        push qword [rax+FRAME_RSP*8]      ; rsp
        push qword [rax+FRAME_FLAGS*8]   ; rflags
        push qword 0x08   ; cs        
        push qword [rax+FRAME_RIP*8]   ; rip
        mov rax, [rax+FRAME_RAX*8]
        iretq
.end:

global_func geterr
geterr:
        pop rbx            ; error code - put this in the frame
        jmp getrip
.end:

        interrupts equ 0x30

global_data interrupt_size
interrupt_size:
        dd interrupts
.end:

global interrupt0
global interrupt1
vectors:        
        %assign i 0                
        %rep interrupts
        interrupt %+ i:
        push qword i
        jmp interrupt_common
        %assign i i+1        
        %endrep

global_func read_msr
read_msr:
        mov rcx, rdi
        mov rax, 0
        rdmsr
        shl rdx, 0x20
        or rax, rdx
        ret
.end:

global_func write_msr
write_msr:
        mov rcx, rdi
        mov rax, rsi
        mov rdx, rsi
        shr rdx, 0x20
        wrmsr
        ret
.end:

global_func cpuid
cpuid:
        mov eax, 1
        cpuid
        mov rax, rcx
        shl rax, 0x20
        ;;  its not clear how to clear the top bits of rdx in a more direct fashion
        shl rdx, 0x20
        shr rdx, 0x20                
        or rax, rdx
        ret
.end:

global_func read_xmsr
read_xmsr:
        mov rcx, rdi
        mov rax, 0
        xgetbv
        shl rdx, 0x20
        or rax, rdx
        ret
.end:

global_func write_xmsr
write_xmsr:
        mov rcx, rdi
        mov rax, rsi
        mov rdx, rsi
        shr rdx, 0x20
        xsetbv        
        ret
.end:

_start:
        call init_service
        hlt
.end:




