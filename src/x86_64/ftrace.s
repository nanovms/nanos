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

extern __ftrace_function_fn
extern __ftrace_graph_entry_fn
extern __ftrace_graph_return_fn
extern prepare_ftrace_return
extern ftrace_return_to_handler
extern tracing_on

;; After this is called, the following registers contain:
;;  %rdi - holds IP of tracee (address of function being traced)
;;  %rsi - holds return address (caller of tracee)
;;  %rdx - holds the original %rbp
;;
;; and the stack will look like:
;;  [            |             ]  <-- rsp
;;  [            |             ]
;;  [    <saved frame ctx>     ]
;;  [            |             ]
;;  [            |             ]
;;  [        saved rbp         ]  <-- rbp
;;  [ retaddr (mcount->callee) ]
;;  [        saved rbp         ]
;;  [ retaddr (mcount->callee) ]
;; 
%macro save_mcount_regs 0
    push rbp ; save orig rbp

    ;; setup the prologue to make it look like we are in the callee ;; rather
    ;; than mcount
    push qword [rsp+8] ; push return address to get back to callee
    push rbp ; save orig rbp
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

    ;; save original rbp into rdx
    ;; XXX: Linux does this but rbp already points to the saved rbp ...
    ;; mov rdx, [rsp+(SAVE_REG_SIZE-8)]
    mov rdx, [rbp]
    mov [rsp+FRAME_RBP*8], rdx

    ;; return address (from callee back to caller) into rsi
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
global return_to_handler

mcount:
    ;; check if globally enabled
    test byte [tracing_on], 1
    jz ftrace_stub

    ;; check if enabled on this cpu
    test qword [gs:40], 1
    jnz ftrace_stub

    cmp qword [__ftrace_function_fn], ftrace_stub
    jnz do_trace

    cmp qword [__ftrace_graph_return_fn], ftrace_stub
    jnz trace_graph_caller

    cmp qword [__ftrace_graph_entry_fn], ftrace_stub
    jnz trace_graph_caller

;; fall through to ret
ftrace_stub:
    ret

do_trace:
    save_mcount_regs
    mov r8, [__ftrace_function_fn]
    call r8
    restore_mcount_regs
    ret

trace_graph_caller:
    save_mcount_regs

    ;; args to prepare_ftrace_return are:
    ;;   tracee (rdi)
    ;;   pointer to where caller retaddr is on the stack (rsi)
    ;;   original frame pointer in caller (rdx)

    ;; rdx has the original rbp, which is 8 bytes below the retaddr
    lea rsi, [rdx+8]

    ;; At this point *rsi = (old rsi before the line above)

    ;; need the saved RBP from the caller
    mov rdx, [rdx]

    call prepare_ftrace_return

    restore_mcount_regs
    ret

return_to_handler:
    sub rsp, 32
    
    mov [rsp], rax
    mov [rsp+8], rdx
    mov rdi, rbp

    call ftrace_return_to_handler

    mov rdi, rax
    mov rdx, [rsp+8],
    mov rax, [rsp]

    add rsp, 32

    jmp rdi
