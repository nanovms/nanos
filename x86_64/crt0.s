        global _start
        extern init_service
        
        ;; frame size is 136..? 
extern frame

        ;; xxx - share this with C
%define FRAME_RAX 0
%define FRAME_RBX 1
%define FRAME_RCX 2
%define FRAME_RDX 3
%define FRAME_RSI 4
%define FRAME_RDI 5
%define FRAME_RBP 6
%define FRAME_RSP 7
%define FRAME_R8 8
%define FRAME_R9 9 
%define FRAME_R10 10
%define FRAME_R11 11
%define FRAME_R12 12
%define FRAME_R13 13
%define FRAME_R14 14
%define FRAME_R15 15
%define FRAME_VECTOR 16
%define FRAME_RIP 17
%define FRAME_FLAGS 18
%define FRAME_FS 19
%define FRAME_GS 20
%define FS_MSR 0xc0000100
        
;;; optimize and merge - frame is loaded into rbx
global frame_enter
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
        mov rax, [rbx+FRAME_RIP*8]
        mov rsp, [rbx+FRAME_RSP*8]                
        push rax
        mov rax, [rbx+FRAME_FLAGS*8]        
        push rax        
        mov rax, [rbx+FRAME_RAX*8]
        mov rbx, [rbx+FRAME_RBX*8]                
        popf
        ret

;; syscall save and restore doesn't always have to be a full frame        
extern syscall
global syscall_enter
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
        call syscall
        mov rbx, [frame]
        mov [rbx + FRAME_RAX], rax
        jmp frame_enter

        
extern common_handler
interrupt_common:
        push rax
        mov rax, [frame]
        mov [rax+FRAME_RBX*8], rbx
        mov [rax+FRAME_RCX*8], rcx
        mov [rax+FRAME_RDX*8], rdx
        mov [rax+FRAME_RSP*8], rsp   ;ehh, off by 16 plus the stack frame
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
        pop rbx            ; actually eax
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
        mov [rax+FRAME_RSP*8], rbx  ; 
                           ; ss plus padding at the top  
        call common_handler

geterr:
        pop rbx            ; error code - put this in the frame
        jmp getrip
        
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

global read_msr
read_msr:
        mov rcx, rdi
        mov rax, 0
        rdmsr
        shl rdx, 0x20
        or rax, rdx
        ret

global write_msr
write_msr:
        mov rcx, rdi
        mov rax, rsi
        mov rdx, rsi
        shr rdx, 0x20
        wrmsr
        ret
        
global cpuid
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
        
global read_xmsr
read_xmsr:
        mov rcx, rdi
        mov rax, 0
        xgetbv
        shl rdx, 0x20
        or rax, rdx
        ret

global write_xmsr
write_xmsr:
        mov rcx, rdi
        mov rax, rsi
        mov rdx, rsi
        shr rdx, 0x20
        xsetbv        
        ret

_start:
        call init_service
        hlt




