%macro TO_HEX 1
	add %1, 0x30
	cmp %1, 0x3a
	jl %%skip
	add %1, 0x41 - 0x3a
%%skip:
%endmacro


%ifdef DEBUG
%macro TTY_OUT 1
	mov al, %1
	call tty_out
%endmacro


%macro TTY_OUT_HEX 1
	mov al, %1
	call tty_out_hex
%endmacro


%macro TTY_OUT_NL 0
	mov al, 0xd
	call tty_out
	mov al, 0xa
	call tty_out
%endmacro
%else
%macro TTY_OUT 1
%endmacro
%macro TTY_OUT_HEX 1
%endmacro
%macro TTY_OUT_NL 0
%endmacro
%endif


tty_out:
	push ax
	push bx
	mov ah, 0eh
	xor bh, bh
	int 10h
	call serial_out
	pop bx
	pop ax
	ret


tty_out_hex:
	push ax

	mov ah, al
	shr ah, 4
	TO_HEX ah

	and al, 0xf
	TO_HEX al

	xchg al, ah
	call tty_out
	xchg al, ah
	call tty_out

	pop ax
	ret


tty_out_bytes:
	cld
.loop:
	lodsb
	call tty_out_hex
	TTY_OUT ' '
	dec cx
	jnz .loop
	ret


serial_out:
	push ax
	push dx

	xor dx, dx
	mov ah, 1
	int 0x14

	pop dx
	pop ax
        ret
