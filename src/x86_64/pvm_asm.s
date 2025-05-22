%include "x86.inc"

%macro pvm_event_common 0
    mov r11, [gs:8]	    ; current context / frame start
    mov [r11+FRAME_RAX*8], rax
    mov [r11+FRAME_RBX*8], rbx
    mov [r11+FRAME_RDX*8], rdx
    mov [r11+FRAME_RSI*8], rsi
    mov [r11+FRAME_RDI*8], rdi
    mov [r11+FRAME_RBP*8], rbp
    mov [r11+FRAME_R8*8], r8
    mov [r11+FRAME_R9*8], r9
    mov [r11+FRAME_R10*8], r10
    mov [r11+FRAME_R12*8], r12
    mov [r11+FRAME_R13*8], r13
    mov [r11+FRAME_R14*8], r14
    mov [r11+FRAME_R15*8], r15
    save_extended_registers r11
%endmacro

extern pvm_event

global_func pvm_event_entry
pvm_event_entry:
    ; exceptions and interrupts in user mode
    pvm_event_common
    mov rdi, 1
    jmp pvm_event
    times (pvm_event_entry + 256) - $ db 0x90   ; pad with NOPs until offset 256
    ; exceptions in supervisor mode
    pvm_event_common
    pop rcx	; error_code + vector
    mov [r11+FRAME_ERROR_CODE*8], ecx
    shr rcx, 32
    mov [r11+FRAME_VECTOR*8], ecx
    pop rcx	; rip
    mov [r11+FRAME_RIP*8], rcx
    pop rcx	; cs
    mov [r11+FRAME_CS*8], rcx
    pop rcx	; eflags
    mov [r11+FRAME_EFLAGS*8], rcx
    pop rcx	; rsp
    mov [r11+FRAME_RSP*8], rcx
    pop rcx	; ss
    mov [r11+FRAME_SS*8], rcx
    pop rcx	; rcx
    mov [r11+FRAME_RCX*8], rcx
    pop rcx	; r11
    mov [r11+FRAME_R11*8], rcx
    mov rdi, 0
    jmp pvm_event
    times (pvm_event_entry + 512) - $ db 0x90   ; pad with NOPs until offset 512
    ; interrupts in supervisor mode
    pvm_event_common
    mov rdi, 1
    jmp pvm_event
.end:

extern pvm_syscall

global_func pvm_syscall_entry
pvm_syscall_entry:
    mov r11, [gs:8]     ; current context / frame start
    mov [r11+FRAME_VECTOR*8], rax
    mov [r11+FRAME_RBX*8], rbx
    mov [r11+FRAME_RDX*8], rdx
    mov [r11+FRAME_RBP*8], rbp
    mov [r11+FRAME_RSI*8], rsi
    mov [r11+FRAME_RDI*8], rdi
    mov [r11+FRAME_R8*8], r8
    mov [r11+FRAME_R9*8], r9
    mov [r11+FRAME_R10*8], r10
    mov [r11+FRAME_R12*8], r12
    mov [r11+FRAME_R13*8], r13
    mov [r11+FRAME_R14*8], r14
    mov [r11+FRAME_R15*8], r15
    save_extended_registers r11
    ; switch to syscall context
    mov rbx, [gs:24]
    mov [gs:8], rbx
    mov rsp, [rbx+FRAME_STACK_TOP*8]
    mov rdi, r11
    jmp pvm_syscall
.end:

global_func pvm_event_return
pvm_event_return:
    mov al, [rdi+FRAME_CS*8]
    and al, 0x3 ; check for CPL != 0 (return to user mode)
    jnz ret_to_user

    mov rax, [rdi+FRAME_FSBASE*8]
    mov rcx, FS_MSR
    mov rdx, rax
    shr rdx, 0x20
    wrmsr

    load_extended_registers rdi
    mov rax, [rdi+FRAME_RAX*8]
    mov rbx, [rdi+FRAME_RBX*8]
    mov rdx, [rdi+FRAME_RDX*8]
    mov rbp, [rdi+FRAME_RBP*8]
    mov rsi, [rdi+FRAME_RSI*8]
    mov r8, [rdi+FRAME_R8*8]
    mov r9, [rdi+FRAME_R9*8]
    mov r10, [rdi+FRAME_R10*8]
    mov r12, [rdi+FRAME_R12*8]
    mov r13, [rdi+FRAME_R13*8]
    mov r14, [rdi+FRAME_R14*8]
    mov r15, [rdi+FRAME_R15*8]
    push qword [rdi+FRAME_R11*8]
    push qword [rdi+FRAME_RCX*8]
    push qword [rdi+FRAME_SS*8]
    push qword [rdi+FRAME_RSP*8]
    push qword [rdi+FRAME_EFLAGS*8]
    push qword [rdi+FRAME_CS*8]
    push qword [rdi+FRAME_RIP*8]
    push qword [rdi+FRAME_ERROR_CODE*8]
    mov rdi, [rdi+FRAME_RDI*8]
.end:

global_func pvm_rets
pvm_rets:
    syscall
.end:

ret_to_user:
    mov rax, [rdi+FRAME_FSBASE*8]
    mov rcx, FS_MSR
    mov rdx, rax
    shr rdx, 0x20
    wrmsr

    load_extended_registers rdi
    mov rax, [rdi+FRAME_RAX*8]
    mov rbx, [rdi+FRAME_RBX*8]
    mov rdx, [rdi+FRAME_RDX*8]
    mov rbp, [rdi+FRAME_RBP*8]
    mov rsi, [rdi+FRAME_RSI*8]
    mov r8, [rdi+FRAME_R8*8]
    mov r9, [rdi+FRAME_R9*8]
    mov r10, [rdi+FRAME_R10*8]
    mov r12, [rdi+FRAME_R12*8]
    mov r13, [rdi+FRAME_R13*8]
    mov r14, [rdi+FRAME_R14*8]
    mov r15, [rdi+FRAME_R15*8]
    mov rdi, [rdi+FRAME_RDI*8]
global_func pvm_retu
pvm_retu:
    syscall
.end:
