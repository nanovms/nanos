        ;;  this isn't c runtime zero, just some assembly stuff

%macro global_func 1
	global %1:function (%1.end - %1)
%endmacro
%macro global_data 1
	global %1:data (%1.end - %1)
%endmacro
        
global_func _start
        extern init_service
        
extern running_frame
%include "frame.inc"
        
%define FS_MSR 0xc0000100
        
extern common_handler
interrupt_common:
        push rax
        mov rax, [running_frame]
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
        mov [rax+FRAME_RAX*8], rbx
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

        mov rbx, [running_frame]

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

global_func geterr
geterr:
        pop rbx
        mov [rax+FRAME_ERROR_CODE*8], rbx
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

;; syscall save and restore doesn't always have to be a full frame
extern syscall
global_func syscall_enter
syscall_enter:
        push rax
        mov rax, [running_frame]
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
        mov rbx, [running_frame]
        jmp frame_return
.end:

global_func frame_return
frame_return:
        mov rax, [rbx+FRAME_FS*8]
        mov rcx, FS_MSR
        mov rdx, rax
        shr rdx, 0x20
        wrmsr ;; move fs, consider macro

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

global_func install_gdt64_and_tss
install_gdt64_and_tss:
        lgdt [GDT64.Pointer]
        mov rax, TSS
        mov [GDT64 + GDT64.TSS + 2], ax
        shr rax, 0x10
        mov [GDT64 + GDT64.TSS + 4], al
        mov [GDT64 + GDT64.TSS + 7], ah
        shr rax, 0x10
        mov [GDT64 + GDT64.TSS + 8], eax
        mov rax, GDT64.TSS
        ltr ax
        ret
.end:

        ;; set this crap up again so we can remove the stage2 one from low memory
align 16                        ; necessary?
GDT64:  ; Global Descriptor Table (64-bit).
        ;;  xxx - clean this up with a macro
        .Null: equ $ - GDT64 ; The null descriptor.
        dw 0  ; Limit (low).
        dw 0  ; Base (low).
        db 0  ; Base (middle)
        db 0  ; Access.
        db 0  ; Granularity.
        db 0  ; Base (high).
        .Code: equ $ - GDT64 ; The code descriptor.
        dw 0  ; Limit (low).
        dw 0  ; Base (low).
        db 0  ; Base (middle)
        db 10011010b    ; Access (exec/read).
        db 00100000b    ; Granularity.
        db 0            ; Base (high).
        .Data: equ $ - GDT64 ; The data descriptor.
        dw 0         ; Limit (low).
        dw 0         ; Base (low).
        db 0         ; Base (middle)
        db 10010010b ; Access (read/write).
        db 00000000b ; Granularity.
        db 0         ; Base (high).
        .CodeAgain: equ $ - GDT64 ; The code descriptor for sysret into long mode
        dw 0  ; Limit (low).
        dw 0  ; Base (low).
        db 0  ; Base (middle)
        db 10011010b    ; Access (exec/read).
        db 00100000b    ; Granularity.
        db 0            ; Base (high).
        .TSS: equ $ - GDT64     ; TSS descriptor (system segment descriptor - 64bit mode)
        dw (TSS.end - TSS)      ; Limit (low)
        dw 0                    ; Base [15:0] [fill in base at runtime, for I lack nasm sauce]
        db 0                    ; Base [23:16]
        db 10001001b            ; Present, long mode type available TSS
        db 00000000b            ; byte granularity
        db 0                    ; Base [31:24]
        dd 0                    ; Base [63:32]
        dd 0                    ; Reserved
        .Pointer:    ; The GDT-pointer.
        dw $ - GDT64 - 1    ; Limit.
        dq GDT64            ; 64 bit Base.

        align 16                ; XXX ??
global_data TSS
TSS:                            ; 64 bit TSS
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
.end:
