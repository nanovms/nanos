        ;;  this isn't c runtime zero, just some assembly stuff

%include "x86.inc"

global_func _start
extern  init_service

%ifdef DEBUG
%include "debug.inc"
%endif

;; 2 least significant bits of CS (CPL) == 0 -> kernel mode - no swapgs
%macro check_swapgs 1
        test qword [rsp + %1], 0x03
        jz %%skip
        swapgs
%%skip:
%endmacro

;; rdi is frame
%macro load_seg_base 1
%if (%1 == FRAME_FSBASE)
        mov rax, [rdi+FRAME_FSBASE*8]
        mov rcx, FS_MSR
%else
        mov rax, [rdi+FRAME_GSBASE*8]
        mov rcx, KERNEL_GS_MSR
%endif
        mov rdx, rax
        shr rdx, 0x20
        wrmsr
%endmacro

;;;  helper so userspace can save a frame without
;;; 
global xsave        
xsave:
        save_extended_registers rdi
        ret
        
;; stack frame upon entry:
;;
;; ss
;; rsp
;; rflags
;; cs
;; rip
;; [error code - if vec 0xe or 0xd]
;; vector <- rsp

%macro save_current_context 0
        push rbx
        mov rbx, [gs:8]         ; current_context / frame start
        mov [rbx+FRAME_RAX*8], rax
        mov [rbx+FRAME_RCX*8], rcx
        mov [rbx+FRAME_RDX*8], rdx
        mov [rbx+FRAME_RSI*8], rsi
        mov [rbx+FRAME_RDI*8], rdi
        mov [rbx+FRAME_RBP*8], rbp
        mov [rbx+FRAME_R8*8], r8
        mov [rbx+FRAME_R9*8], r9
        mov [rbx+FRAME_R10*8], r10
        mov [rbx+FRAME_R11*8], r11
        mov [rbx+FRAME_R12*8], r12
        mov [rbx+FRAME_R13*8], r13
        mov [rbx+FRAME_R14*8], r14
        mov [rbx+FRAME_R15*8], r15
        pop rax            ; rbx
        mov [rbx+FRAME_RBX*8], rax
        save_extended_registers rbx
%endmacro

%macro interrupt_common_top 0
        save_current_context
        mov rdi, cr2
        mov [rbx+FRAME_CR2*8], rdi
        pop rax            ; vector
        mov [rbx+FRAME_VECTOR*8], rax
%endmacro
        
extern common_handler

%macro interrupt_common_bottom 0
        pop rax            ; rip
        mov [rbx+FRAME_RIP*8], rax
        pop rax            ; cs
        mov [rbx+FRAME_CS*8], rax
        pop rax            ; rflags
        mov [rbx+FRAME_EFLAGS*8], rax
        pop rax            ; rsp
        mov [rbx+FRAME_RSP*8], rax
        pop rax            ; ss         
        mov [rbx+FRAME_SS*8], rax
        cld
        call common_handler
        ; noreturn               
%endmacro

;; just write a generic one that takes rax, rcx and arguments and stores in a u64[3]
global xsave_features
xsave_features :
	push rcx
	push rbx
        mov rax, 0xd
        mov rcx, 0x1
        cpuid
        pop rbx
        pop rcx            
        ret
        
global interrupt_entry_with_ec
interrupt_entry_with_ec:
        check_swapgs 24
        interrupt_common_top
        pop rax
        mov [rbx+FRAME_ERROR_CODE*8], rax
        interrupt_common_bottom
        hlt                     ; no return

global interrupt_entry
interrupt_entry:
        check_swapgs 16
        interrupt_common_top
        interrupt_common_bottom
        hlt                     ; no return

global frame_return
frame_return:
        mov qword [rdi+FRAME_FULL*8], 0
        ; check for syscall (CS CPL==2)
        mov al, [rdi+FRAME_CS*8]
        and al, 3
        cmp al, 2
        je syscall_return

        push qword [rdi+FRAME_SS*8]    ; ss
        push qword [rdi+FRAME_RSP*8]   ; rsp
        push qword [rdi+FRAME_EFLAGS*8] ; rflags
        push qword [rdi+FRAME_CS*8]    ; cs
        push qword [rdi+FRAME_RIP*8]   ; rip

        ; before iret back to userspace, restore fs and gs base and swapgs
        cmp qword [rsp + 8], 0x08
        je .skip

        ;; XXX should be lazy?
        load_seg_base FRAME_FSBASE
        load_seg_base FRAME_GSBASE
        swapgs
.skip:
        load_extended_registers rdi
        mov rax, [rdi+FRAME_RAX*8]
        mov rbx, [rdi+FRAME_RBX*8]
        mov rcx, [rdi+FRAME_RCX*8]
        mov rdx, [rdi+FRAME_RDX*8]
        mov rbp, [rdi+FRAME_RBP*8]
        mov rsi, [rdi+FRAME_RSI*8]
        mov r8, [rdi+FRAME_R8*8]
        mov r9, [rdi+FRAME_R9*8]
        mov r10, [rdi+FRAME_R10*8]
        mov r11, [rdi+FRAME_R11*8]
        mov r12, [rdi+FRAME_R12*8]
        mov r13, [rdi+FRAME_R13*8]
        mov r14, [rdi+FRAME_R14*8]
        mov r15, [rdi+FRAME_R15*8]
        mov rdi, [rdi+FRAME_RDI*8]
        iretq

        interrupts equ 0x100

global_data n_interrupt_vectors
n_interrupt_vectors:
        dd interrupts
.end:
global_data interrupt_vector_size
interrupt_vector_size:
        dd interrupt1 - interrupt0
.end:

global interrupt_vectors
interrupt_vectors:
%assign i 0
%rep interrupts
        interrupt %+ i:
        push qword i
%if (i == 0xe || i == 0xd)
        jmp interrupt_entry_with_ec
%else
        jmp interrupt_entry
%endif
%assign i i+1
%endrep

;; syscall save and restore doesn't always have to be a full frame
extern syscall
global_func syscall_enter
syscall_enter:
        swapgs
        mov [gs:32], rdi        ; save rdi in tmp
        mov rdi, [gs:8]         ; current context
        mov [rdi+FRAME_VECTOR*8], rax
        mov [rdi+FRAME_RBX*8], rbx
        mov [rdi+FRAME_RDX*8], rdx
        mov [rdi+FRAME_RBP*8], rbp
        mov [rdi+FRAME_RSI*8], rsi
        mov [rdi+FRAME_R8*8], r8
        mov [rdi+FRAME_R9*8], r9
        mov [rdi+FRAME_R10*8], r10
        mov [rdi+FRAME_EFLAGS*8], r11
        mov [rdi+FRAME_R12*8], r12
        mov [rdi+FRAME_R13*8], r13
        mov [rdi+FRAME_R14*8], r14
        mov [rdi+FRAME_R15*8], r15
        mov [rdi+FRAME_RIP*8], rcx
        mov [rdi+FRAME_RSP*8], rsp
        mov rax, [gs:32]
        mov qword [rdi+FRAME_RDI*8], rax
        and byte [rdi+FRAME_CS*8], ~1     ; clear low bit of CS to indicate syscall (CPL==2)
        save_extended_registers rdi
        mov rax, syscall
        mov rax, [rax]
        mov rbx, [gs:24]        ; switch to syscall context
        mov [gs:8], rbx
        mov rsp, [rbx+FRAME_STACK_TOP*8]
        cld
        jmp rax
.end:

;; must follow syscall_enter
syscall_return:
        ; set CPL 3
        or byte [rdi+FRAME_CS*8], 3
        ;; XXX lazy?
        load_seg_base FRAME_FSBASE
        load_seg_base FRAME_GSBASE
        load_extended_registers rdi
        mov rax, [rdi+FRAME_RAX*8]
        mov rbx, [rdi+FRAME_RBX*8]
        mov rdx, [rdi+FRAME_RDX*8]
        mov rbp, [rdi+FRAME_RBP*8]
        mov rsi, [rdi+FRAME_RSI*8]
        mov r8, [rdi+FRAME_R8*8]
        mov r9, [rdi+FRAME_R9*8]
        mov r10, [rdi+FRAME_R10*8]
        mov r11, [rdi+FRAME_EFLAGS*8] ; flags saved from r11 on syscall
        mov r12, [rdi+FRAME_R12*8]
        mov r13, [rdi+FRAME_R13*8]
        mov r14, [rdi+FRAME_R14*8]
        mov r15, [rdi+FRAME_R15*8]
        mov rsp, [rdi+FRAME_RSP*8]
        mov rcx, [rdi+FRAME_RIP*8]
        mov rdi, [rdi+FRAME_RDI*8]
        swapgs
        o64 sysret
.end:

extern context_suspend_finish

global_func context_suspend
context_suspend:
        pushfq
        cli
        save_current_context
        pop rax                 ; rflags
        mov [rbx+FRAME_EFLAGS*8], rax
        pop rax                 ; return addr
        mov [rbx+FRAME_RIP*8], rax
        mov [rbx+FRAME_CS*8], cs
        mov [rbx+FRAME_SS*8], ss
        mov [rbx+FRAME_RSP*8], rsp
        mov rdi, rbx
        jmp context_suspend_finish      ; finish in C
.end:

global_func err_frame_save
err_frame_save:
        mov [rdi+ERR_FRAME_RBX*8], rbx
        mov [rdi+ERR_FRAME_RBP*8], rbp
        mov [rdi+ERR_FRAME_R12*8], r12
        mov [rdi+ERR_FRAME_R13*8], r13
        mov [rdi+ERR_FRAME_R14*8], r14
        mov [rdi+ERR_FRAME_R15*8], r15
        mov rax, rsp
        add rax, 8
        mov [rdi+ERR_FRAME_RSP*8], rax
        mov rax, [rsp]
        mov [rdi+ERR_FRAME_RIP*8], rax
        mov rax, 0
        ret
.end:

global_func err_frame_apply
err_frame_apply:
        mov rax, [rdi+ERR_FRAME_RBX*8]
        mov [rsi+FRAME_RBX*8], rax
        mov rax, [rdi+ERR_FRAME_RBP*8]
        mov [rsi+FRAME_RBP*8], rax
        mov rax, [rdi+ERR_FRAME_R12*8]
        mov [rsi+FRAME_R12*8], rax
        mov rax, [rdi+ERR_FRAME_R13*8]
        mov [rsi+FRAME_R13*8], rax
        mov rax, [rdi+ERR_FRAME_R14*8]
        mov [rsi+FRAME_R14*8], rax
        mov rax, [rdi+ERR_FRAME_R15*8]
        mov [rsi+FRAME_R15*8], rax
        mov rax, [rdi+ERR_FRAME_RSP*8]
        mov [rsi+FRAME_RSP*8], rax
        mov rax, [rdi+ERR_FRAME_RIP*8]
        mov [rsi+FRAME_RIP*8], rax
        mov rax, 1			; return value for context_set_err()
        mov [rsi+FRAME_RAX*8], rax
        ret
.end:
        
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
        xor rdx, rdx
        call init_service
        hlt
.end:

%define TSS_SIZE 0x68
global_func install_gdt64_and_tss
install_gdt64_and_tss:
        lgdt [rcx]
        mov rax, rsi
        mov [rdi], word TSS_SIZE ; limit
        mov [rdi + 2], ax   ; base [15:0]
        shr rax, 0x10
        mov [rdi + 4], al ; base [23:16]
        mov [rdi + 5], byte 10001001b ; present, 64-bit TSS available
        mov [rdi + 7], ah ; base [31:24]
        shr rax, 0x10
        mov [rdi + 8], eax ; base [63:32]
        sub rdi, rdx	; calculate offset of TSS descriptor in GDT
        ltr di
        mov rax, 0x10   ; assumes kernel data segment is at offset 0x10
        mov ss, rax
        mov ds, rax
        mov es, rax
        pop rax
        push 0x08       ; assumes kernel code segment is at offset 0x08
        push rax
        o64 retf
.end:

;; hypercall page used by xen and hyper-v
align 4096
global hypercall_page
hypercall_page:
        times 4096 db 0

extern pvh_start32

section .note.Xen noalloc
align 4
        dd 4 ; name size
        dd 4 ; data size
        dd 18 ; type (XEN_ELFNOTE_PHYS32_ENTRY)
align 4
        db 'Xen',0x00 ; name
align 4
        dd pvh_start32  ; data
