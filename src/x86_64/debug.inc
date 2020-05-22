COM1_PORT equ 0x3f8


; spoils dx
serial_out:
	push ax
	xchg al, ah
	mov dx, COM1_PORT + 5
.wait:
	in al, dx
	and al, 0x20
	jz .wait
	xchg al, ah
	mov dx, COM1_PORT
	out dx, al
	pop ax
	ret


%macro TO_HEX 1
	add %1, 0x30
	cmp %1, 0x3a
	jl %%skip
	add %1, 0x41 - 0x3a
%%skip:
%endmacro


%ifndef NO_SERIAL_OUT_HEX
; spoils dx
serial_out_hex:
	push ax

	mov ah, al
	shr ah, 4
	TO_HEX ah

	and al, 0xf
	TO_HEX al

	xchg al, ah
	call serial_out
	xchg al, ah
	call serial_out

	pop ax
	ret
%endif


%ifndef NO_SERIAL_OUT_BYTES
serial_out_bytes:
	push ax
	push dx
.loop:
	mov al, [esi]
	call serial_out_hex
	mov al, ' '
	call serial_out
	inc esi
	dec ecx
	jnz .loop
	pop dx
	pop ax
	ret
%endif


%macro PUTCHAR 1
%if %1 != al
	push dx
	push ax
	mov al, %1
%endif
	call serial_out
%if %1 != al
	pop ax
	pop dx
%endif
%endmacro


%macro PUTSTRING 1
%if __BITS__ == 64
	section .data
%else
	jmp short %%begin
%endif
%%data: db %1
%%data_end:
%if __BITS__ == 64
	section .text
%else
%%begin:
%endif
	push dx
	push ax
%if __BITS__ == 64
	push rbx
	mov rbx, %%data
%else
	push ebx
	mov ebx, %%data
%endif
%%next:
%if __BITS__ == 64
	mov al, [rbx]
	inc rbx
%else
	mov al, [ebx]
	inc ebx
%endif
	call serial_out
%if __BITS__ == 64
	cmp rbx, %%data_end
%else
	cmp ebx, %%data_end
%endif
	jne %%next
%if __BITS__ == 64
	pop rbx
%else
	pop ebx
%endif
	pop ax
	pop dx
%endmacro


%macro PUTBYTE 1
%if %1 != al
	push dx
	push ax
	mov al, %1
%endif
	call serial_out_hex
%if %1 != al
	pop ax
	pop dx
%endif
%endmacro


%macro PUTWORD 1
%if %1 != ax
	push dx
	push ax
	mov ax, %1
%endif
	xchg al, ah
	PUTBYTE al
	xchg al, ah
	PUTBYTE al
%if %1 != ax
	pop ax
	pop dx
%endif
%endmacro


%macro PUTDWORD 1
%if %1 != eax
	push dx
	push eax
	mov eax, %1
%endif
	ror eax, 16
	PUTWORD ax
	ror eax, 16
	PUTWORD ax
%if %1 != eax
	pop eax
	pop dx
%endif
%endmacro


%macro PUTQWORD 1
%if %1 != rax
	push dx
	push rax
	mov rax, %1
%endif
	ror rax, 32
	PUTDWORD eax
	ror rax, 32
	PUTDWORD eax
%if %1 != rax
	pop rax
	pop dx
%endif
%endmacro
