        ;;  this isn't c runtime zero, just some assembly stuff

%macro global_func 1
	global %1:function (%1.end - %1)
%endmacro
%macro global_data 1
	global %1:data (%1.end - %1)
%endmacro
        
global_func _start
extern  init_service

%include "frame.inc"
        
%define FS_MSR        0xc0000100
%define KERNEL_GS_MSR 0xc0000102

;; CS == 0x8 is kernel mode - no swapgs
%macro check_swapgs 1
        cmp qword [rsp + %1], 0x08
        je %%skip
        swapgs
%%skip:
%endmacro

;; rbx is frame
%macro load_seg_base 1
%if (%1 == FRAME_FSBASE)
        mov rax, [rbx+FRAME_FSBASE*8]
        mov rcx, FS_MSR
%else
        mov rax, [rbx+FRAME_GSBASE*8]
        mov rcx, KERNEL_GS_MSR
%endif
        mov rdx, rax
        shr rdx, 0x20
        wrmsr
%endmacro

;; stack frame upon entry:
;;
;; ss
;; rsp
;; rflags
;; cs
;; rip
;; [error code - if vec 0xe or 0xd]
;; vector <- rsp

%macro interrupt_common_top 0
        push rbx
        mov rbx, [gs:0]
        mov rbx, [rbx+8]        ; running_frame
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
        mov rdi, cr2
        mov [rbx+FRAME_CR2*8], rdi
        pop rax            ; rbx
        mov [rbx+FRAME_RBX*8], rax
        pop rax            ; vector
        mov [rbx+FRAME_VECTOR*8], rax
%endmacro

extern common_handler

%macro interrupt_common_bottom 0
        pop rax            ; eip
        mov [rbx+FRAME_RIP*8], rax
        pop rax            ; cs
        mov [rbx+FRAME_CS*8], rax
        pop rax            ; rflags
        mov [rbx+FRAME_FLAGS*8], rax
        pop rax            ; rsp?
        mov [rbx+FRAME_RSP*8], rax
        pop rax            ; ss         
        mov [rbx+FRAME_SS*8], rax
        cld
        call common_handler
%endmacro

global interrupt_entry_with_ec
interrupt_entry_with_ec:
        check_swapgs 24
        interrupt_common_top
        pop rax
        mov [rbx+FRAME_ERROR_CODE*8], rax
        interrupt_common_bottom
        jmp interrupt_exit

global interrupt_entry
interrupt_entry:
        check_swapgs 16
        interrupt_common_top
        interrupt_common_bottom
        ; fall through to interrupt_exit

global interrupt_exit
interrupt_exit:
        mov rbx, [gs:0]
        mov rbx, [rbx+8]        ; running_frame

        push qword [rbx+FRAME_SS*8]    ; ss
        push qword [rbx+FRAME_RSP*8]   ; rsp
        push qword [rbx+FRAME_FLAGS*8] ; rflags
        push qword [rbx+FRAME_CS*8]    ; cs
        push qword [rbx+FRAME_RIP*8]   ; rip

        ; before iret back to userspace, restore fs and gs base and swapgs
        cmp qword [rsp + 8], 0x08
        je .skip
        load_seg_base FRAME_FSBASE
        load_seg_base FRAME_GSBASE
        swapgs
.skip:
        mov rax, [rbx+FRAME_RAX*8]
        mov rcx, [rbx+FRAME_RCX*8]
        mov rdx, [rbx+FRAME_RDX*8]
        mov rbp, [rbx+FRAME_RBP*8]
        mov rsi, [rbx+FRAME_RSI*8]
        mov rdi, [rbx+FRAME_RDI*8]
        mov r8, [rbx+FRAME_R8*8]
        mov r9, [rbx+FRAME_R9*8]
        mov r10, [rbx+FRAME_R10*8]
        mov r11, [rbx+FRAME_R11*8]
        mov r12, [rbx+FRAME_R12*8]
        mov r13, [rbx+FRAME_R13*8]
        mov r14, [rbx+FRAME_R14*8]
        mov r15, [rbx+FRAME_R15*8]
        mov rbx, [rbx+FRAME_RBX*8]
        iretq

        interrupts equ 0x30

        ;; until we can build gdt dynamically...
        cpus equ 0x10

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
        push rax
        mov rax, [gs:0]
        mov rax, [rax+8]        ; running_frame
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
        mov rbx, [gs:0]
        mov rsp, [rbx+16]       ; syscall_stack
        cld
        call rax
        mov rbx, [gs:0]
        mov rbx, [rbx+8]        ; running_frame
        ;; fall through to frame_return
.end:

;; must follow syscall_enter
global_func frame_return
frame_return:
        load_seg_base FRAME_FSBASE
        load_seg_base FRAME_GSBASE

        mov rax, rbx

        mov rbx, [rax+FRAME_RBX*8]
        mov rdx, [rax+FRAME_RDX*8]
        mov rbp, [rax+FRAME_RBP*8]
        mov rsi, [rax+FRAME_RSI*8]
        mov rdi, [rax+FRAME_RDI*8]
        mov r8, [rax+FRAME_R8*8]
        mov r9, [rax+FRAME_R9*8]
        mov r10, [rax+FRAME_R10*8]
        mov r11, [rax+FRAME_FLAGS*8] ; flags saved from r11 on syscall
        mov r12, [rax+FRAME_R12*8]
        mov r13, [rax+FRAME_R13*8]
        mov r14, [rax+FRAME_R14*8]
        mov r15, [rax+FRAME_R15*8]
        mov rsp, [rax+FRAME_RSP*8]
        mov rcx, [rax+FRAME_RIP*8]
        mov rax, [rax+FRAME_RAX*8]
        swapgs
        o64 sysret
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
        call init_service
        hlt
.end:

%define TSS_SIZE 0x68
global_func install_gdt64_and_tss
install_gdt64_and_tss:
        lgdt [GDT64.Pointer]
        mov rax, TSS
        imul rsi, rdi, TSS_SIZE
        add rax, rsi
        imul rdi, rdi, 0x10
        add rdi, GDT64.TSS
        mov [GDT64 + rdi], word TSS_SIZE ; limit
        mov [GDT64 + rdi + 2], ax   ; base [15:0]
        shr rax, 0x10
        mov [GDT64 + rdi + 4], al ; base [23:16]
        mov [GDT64 + rdi + 5], byte 10001001b ; present, 64-bit TSS available
        mov [GDT64 + rdi + 7], ah ; base [31:24]
        shr rax, 0x10
        mov [GDT64 + rdi + 8], eax ; base [63:32]
        ltr di
        ret
.end:

%define SEG_DESC_G          (1 << 23) ; Granularity
%define SEG_DESC_DB         (1 << 22) ; Code: default size, Data: big
%define SEG_DESC_L          (1 << 21) ; Code: Long (64-bit)
%define SEG_DESC_AVL        (1 << 20) ; Available
%define SEG_DESC_P          (1 << 15) ; Present
%define SEG_DESC_DPL_SHIFT  13
%define SEG_DESC_S          (1 << 12) ; Code/data (vs sys)
%define SEG_DESC_CODE       (1 << 11) ; Code descriptor type (vs data)
%define SEG_DESC_C          (1 << 10) ; Conforming
%define SEG_DESC_RW         (1 << 9)  ; Code: readable, Data: writeable
%define SEG_DESC_A          (1 << 8)  ; Accessed

%define KERN_CODE_SEG_DESC  (SEG_DESC_L | SEG_DESC_P | SEG_DESC_S | SEG_DESC_CODE | SEG_DESC_RW)
%define KERN_DATA_SEG_DESC  (SEG_DESC_P | SEG_DESC_S | SEG_DESC_RW)
%define USER_CODE_SEG_DESC  (SEG_DESC_L | SEG_DESC_P | (3 << SEG_DESC_DPL_SHIFT) | SEG_DESC_S | SEG_DESC_CODE | SEG_DESC_RW)
%define USER_DATA_SEG_DESC  (SEG_DESC_S | (3 << SEG_DESC_DPL_SHIFT) | SEG_DESC_P | SEG_DESC_RW)

        ;; Global Descriptor Table (64-bit).
align 16
GDT64:
        ;; 0x00: null descriptor - unused
        .Null: equ $ - GDT64
        dd 0
        dd 0

        ;; 0x08: kernel code descriptor
        .Code: equ $ - GDT64
        dd 0                       ; limit / base, unused in long mode
        dd KERN_CODE_SEG_DESC

        ;; 0x10: kernel data descriptor
        .Data: equ $ - GDT64
        dd 0
        dd KERN_DATA_SEG_DESC

        ;; 0x18: 32-bit user code descriptor
        ;;       unused, but set as sysret base in STAR_MSR
        .UserCode: equ $ - GDT64
        dd 0
        dd 0

        ;; 0x20: user data descriptor
        .UserData: equ $ - GDT64
        dd 0
        dd USER_DATA_SEG_DESC

        ;; 0x28: 64-bit user code descriptor
        .UserCode64: equ $ - GDT64
        dd 0
        dd USER_CODE_SEG_DESC

        ;; TSS - per-cpu 64-bit system segment descriptors
        ;; Filled in at runtime by install_gdt64_and_tss
        .TSS: equ $ - GDT64
%rep cpus
        dd 0
        dd 0
        dd 0
        dd 0
%endrep
        .Pointer:    ; The GDT-pointer.
        dw $ - GDT64 - 1    ; Limit.
        dq GDT64            ; 64 bit Base.

        align 16                ; XXX ??
global_data TSS
TSS:                            ; 64 bit TSS
%rep cpus
        dd 0                    ; reserved      0x00
        dd 0                    ; RSP0 (low)    0x04
        dd 0                    ; RSP0 (high)   0x08
        dd 0                    ; RSP1 (low)    0x0c
        dd 0                    ; RSP1 (high)   0x10
        dd 0                    ; RSP2 (low)    0x14
        dd 0                    ; RSP2 (high)   0x18
        dd 0                    ; reserved      0x1c
        dd 0                    ; reserved      0x20
        dd 0                    ; IST1 (low)    0x24
        dd 0                    ; IST1 (high)   0x28
        dd 0                    ; IST2 (low)    0x2c
        dd 0                    ; IST2 (high)   0x30
        dd 0                    ; IST3 (low)    0x34
        dd 0                    ; IST3 (high)   0x38
        dd 0                    ; IST4 (low)    0x3c
        dd 0                    ; IST4 (high)   0x40
        dd 0                    ; IST5 (low)    0x44
        dd 0                    ; IST5 (high)   0x48
        dd 0                    ; IST6 (low)    0x4c
        dd 0                    ; IST6 (high)   0x50
        dd 0                    ; IST7 (low)    0x54
        dd 0                    ; IST7 (high)   0x58
        dd 0                    ; reserved      0x5c
        dd 0                    ; reserved      0x60
        dw 0                    ; IOPB offset   0x64
        dw 0                    ; reserved      0x66
%endrep
.end:

;; hypercall page used by xen
align 4096
global hypercall_page
hypercall_page:
        times 4096 db 0
