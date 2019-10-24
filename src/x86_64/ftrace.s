;; BK: the logic here is similar to Linux, but much simpler as we don't have
;; to deal with fentry, dynamic tracing, and other complexities

%include "frame.inc"

;; save callee rip and rbp 
%define SAVE_FRAME_SIZE (8 + 16)

;; must be an even number larger than the largest GPR in the thread frame
%define FRAME_REG_CNT 18

;; size of stack used to save mcount regs in save_mcount_regs
%define SAVE_REG_SIZE (FRAME_REG_CNT*8 + SAVE_FRAME_SIZE)

;; size of mcount call
%define MCOUNT_INSN_SIZE 5

extern __current_ftrace_trace_fn
extern __current_ftrace_graph_return

;; After this is called, the following registers contain:
;;  %rdi - holds rip of tracee (address of function being traced)
;;  %rsi - holds return address of tracee
;;  %rdx - holds the original %rbp
;;
;; and the stack will look like:
;;  [            |             ]  <--- rsp
;;  [            |             ]
;;  [    <saved frame ctx>     ]
;;  [            |             ]
;;  [            |             ]
;;  [           rbp            ]  <--- rbp
;;  [   tracee function addr   ]  <--- moved into rdi and stored in stack(RIP)
;;  [           rbp            ]  <--- moved into rdx and stored in stack(RBP)
;;  [ tracee retaddr in parent ]  <--- moved into rsi 
%macro save_mcount_regs 0
    push rbp
    push qword [rsp+8]
    push rbp
    mov rbp, rsp
 
    ;; we add enough stack to save all the regs, but only need those
    ;; potentially clobbered by mcount
    sub rsp, (SAVE_REG_SIZE - SAVE_FRAME_SIZE)

    mov [rsp+FRAME_RAX*8], rax
    mov [rsp+FRAME_RCX*8], rcx
    mov [rsp+FRAME_RDX*8], rdx
    mov [rsp+FRAME_RSI*8], rsi
    mov [rsp+FRAME_RDI*8], rdi
    mov [rsp+FRAME_R8*8], r8
    mov [rsp+FRAME_R9*8], r9

    ;; save original rbp
    ;; XXX: Linux does this but rbp already points to the saved rbp ...
    ;; mov rdx, [rsp+(SAVE_REG_SIZE-8)]
    mov rdx, [rbp]
    mov [rsp+FRAME_RBP*8], rdx

    ;; return address from parent into rsi
    mov rsi, [rdx+8]

    ;; load rdi with tracee function address and save in rip on stack
    ;; XXX: Linux does this but rbp points us right underneath it ...
    ;; mov rdi, [rsp+SAVE_REG_SIZE]
    mov rdi, [rbp+8]
    mov [rsp+FRAME_RIP*8], rdi

    ;; adjust rdi by the size of the mcount instruction to get the
    ;; return address of the original call, not mcount
    sub rdi, MCOUNT_INSN_SIZE
%endmacro

%macro restore_mcount_regs 0
    mov r9,  [rsp+FRAME_R9*8]
    mov r8,  [rsp+FRAME_R8*8]
    mov rdi, [rsp+FRAME_RDI*8]
    mov rsi, [rsp+FRAME_RSI*8]
    mov rdx, [rsp+FRAME_RDX*8]
    mov rcx, [rsp+FRAME_RCX*8]
    mov rax, [rsp+FRAME_RAX*8]
    mov rbp, [rsp+FRAME_RBP*8]

    add rsp, SAVE_REG_SIZE
%endmacro

global ftrace_stub
global mcount
mcount:
    cmp qword [__current_ftrace_trace_fn], ftrace_stub
    jnz trace

ftrace_stub:
    ret

trace:
    save_mcount_regs
    mov r8, [__current_ftrace_trace_fn]
    call r8
    restore_mcount_regs
    jmp ftrace_stub
