default rel

%include "frame.inc"

%define FS_MSR          0xc0000100
%define KERNEL_GS_MSR   0xc0000102

%macro global_func 1
    global %1:function (%1.end - %1)
%endmacro
%macro global_data 1
    global %1:data (%1.end - %1)
%endmacro

extern use_xsave

%macro load_extended_registers 1
    mov rcx, [%1+FRAME_EXTENDED*8]
    mov al, [use_xsave]
    test al, al
    jnz %%xs
    fxrstor [rcx]
    jmp %%out
%%xs:
    mov edx, 0xffffffff
    mov eax, edx
    xrstor [rcx]
%%out:
%endmacro

%macro save_extended_registers 1
    mov rcx, [%1+FRAME_EXTENDED*8]
    mov al, [use_xsave]
    test al, al
    jnz %%xs
    fxsave [rcx] ; we wouldn't have to do this if we could guarantee no other user thread ran before us
    jmp %%out
%%xs:
    mov edx, 0xffffffff
    mov eax, edx
    xsave [rcx]
%%out:
%endmacro
