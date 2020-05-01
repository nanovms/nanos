base equ 0x7c00

;
; enter real mode
; See also: https://wiki.osdev.org/Real_Mode
;
; assumes that:
; - interrupts are disabled
; - paging is not enabled (we enable it only in stage3)
; - GDT contains 16-bit data and code entries
; - real IDT is effective (we load IDT only in stage3)
%macro ENTER_REAL 0
	; save protected mode stack
	mov [protected_esp], esp

	jmp gdt32.code16:%%prot16	; enter 16-bit protected mode

%%prot16:
	bits 16
	mov bx, gdt32.data16
	mov ss, bx			; 16-bit stack
	mov ds, bx
	mov es, bx
	mov fs, bx
	mov gs, bx

	;; change the processor mode flag
	mov ebx, cr0
	and ebx, ~1
	mov cr0, ebx			; enter real mode
	jmp 0:%%real

%%real:
	xor bx, bx
	mov ss, bx
	mov ds, bx
	mov es, bx
	mov fs, bx
	mov gs, bx

	mov sp, [real_sp]
%endmacro


;
; assumes "bits 16" mode
%macro ENTER_PROTECTED 0
	;; change the processor mode flag
	mov ebx, cr0
	or ebx, 1
	mov cr0, ebx
	jmp gdt32.code32:%%protected

%%protected:
	bits 32
	mov bx, gdt32.data32
	mov ss, bx
	mov ds, bx
	mov es, bx
	mov fs, bx
	mov gs, bx

	mov esp, [protected_esp]
%endmacro


;; entry point
extern centry
section .start


global _start
_start:
	bits 16
	; move stack
	xor ax, ax
	mov ss, ax
	mov eax, base - 0x10
	mov [real_sp], ax
	sub eax, 0x1000			; temporary protected mode stack until newstack() in stage2
					; should not overlap with real mode stack to not trigger SSP
	mov [protected_esp], eax

	; load 32-bit GDT
	lgdt [gdt32.desc]

	ENTER_PROTECTED
        jmp centry


;
; 32-bit GDT
	align 4
gdt32:
	dw 0,0,0,0			;  trash
.code32 equ $ - gdt32
	dw 0xffff,0,0x9a00,0xcf		;  32 bit code
.data32 equ $ - gdt32
	dw 0xffff,0,0x9200,0xcf		;  32 bit data
.code16 equ $ - gdt32
	dw 0xffff,0,0x9a00,0x0		;  16 bit code
.data16 equ $ - gdt32
	dw 0xffff,0,0x9200,0x0		;  16 bit data
.desc:
	dw $ - gdt32 -1
	dd gdt32


protected_esp: dd 0			; protected mode stack pointer
real_sp: dw 0				; real mode stack pointer

dap:
	db dap.end - dap
	db 0
	.sector_count:	dw 0
	.offset:	dw 0
	.segment:	dw 0
	.lba:	        dq 0
.end:


%ifdef USE_AH02
dpt:
	.heads	dw 0
	.spt	dw 0
	.cyls	dw 0
%endif


%ifdef DEBUG
bits 16
%include "tty.inc"
bits 32
%endif


global bios_read_sectors
bios_read_sectors:
	; conform to x86 cdecl
	push ebp
	mov ebp, esp

	push ebx
	push esi
	push edi

	; prepare dap
	mov eax, [ebp + 8]
	mov [dap.offset], ax
	mov eax, [ebp + 12]
	mov [dap.lba], eax
	mov eax, [ebp + 16]
	mov [dap.sector_count], ax

	ENTER_REAL

%ifdef DEBUG
; print DAP
	TTY_OUT 'D'
	TTY_OUT ':'
	mov cx, [dap]
	mov si, dap
	call tty_out_bytes
	TTY_OUT_NL
%endif

%ifndef USE_AH02
; read from the disk
	mov si, dap
	mov ah, 0x42
	mov dl, 0x80			; first drive
	int 0x13
	jc .error
%else
; get disk parameters
	mov ah, 8
	mov dl, 0x80
	int 0x13			; DH = heads - 1, CX[0:5] = spt, CX[8:15]CX[6:7] = cyls - 1
	jc .error

; print result
	TTY_OUT 'O'
	TTY_OUT ':'
	TTY_OUT_HEX dh
	TTY_OUT ':'
	TTY_OUT_HEX ch
	TTY_OUT_HEX cl
	TTY_OUT_NL

; convert to CHS
	xor dl, dl
	xchg dh, dl
	inc dx
	mov [dpt.heads], dx
	mov al, cl
	and ax, 0x3f
	mov [dpt.spt], ax
	shr cl, 6
	xchg cl, ch
	inc cx
	mov [dpt.cyls], cx

; print cyls:heads:spt
	TTY_OUT 'P'
	TTY_OUT ':'
	TTY_OUT_HEX [dpt.cyls + 1]
	TTY_OUT_HEX [dpt.cyls]
	TTY_OUT ':'
	TTY_OUT_HEX [dpt.heads + 1]
	TTY_OUT_HEX [dpt.heads]
	TTY_OUT ':'
	TTY_OUT_HEX [dpt.spt + 1]
	TTY_OUT_HEX [dpt.spt]
	TTY_OUT_NL

.loop:
; print LBA
	TTY_OUT 'L'
	TTY_OUT ':'
	TTY_OUT_HEX [dap.lba+3]
	TTY_OUT_HEX [dap.lba+2]
	TTY_OUT_HEX [dap.lba+1]
	TTY_OUT_HEX [dap.lba+0]
	TTY_OUT_NL

; convert to LBA to CHS
	mov ax, [dap.lba]
	mov dx, [dap.lba + 2]		; DX:AX = LBA
	div word [dpt.spt]		; DX = sector, AX = head * cyl
	mov cx, dx
	inc cx				; CX = sector, AX = head * cyl
	xor dx, dx			; DX:AX = head * cyl
	div word [dpt.heads]		; CX = sector, DX = head, AX = cyl
	mov bx, ax			; CX = sector, DX = head, BX = cyl

; print CHS
	TTY_OUT 'C'
	TTY_OUT ':'
	TTY_OUT_HEX bh
	TTY_OUT_HEX bl
	TTY_OUT ':'
	TTY_OUT_HEX dh
	TTY_OUT_HEX dl
	TTY_OUT ':'
	TTY_OUT_HEX ch
	TTY_OUT_HEX cl
	TTY_OUT_NL

; convert to AH = 02h args
	mov dh, dl			; DH = head
	and cx, 0x3f			; CX = sector
	shl bh, 6
	xchg bh, bl			; BX[8:15]BX[6:7] = cyl
	or cx, bx			; CX[0:5] = sector, CX[6:7]CX[8:15] = cyl

; print args
	TTY_OUT 'I'
	TTY_OUT ':'
	TTY_OUT_HEX dh
	TTY_OUT ':'
	TTY_OUT_HEX ch
	TTY_OUT_HEX cl
	TTY_OUT_NL

; read from the disk
	mov ax, 0x0201			; AH = 02h, sector count = 1
	mov dl, 0x80
	mov bx, [dap.offset]
	int 0x13
	jc .error

	add word [dap.offset], 512
	inc dword [dap.lba]
	dec word [dap.sector_count]
	jnz .loop
%endif
	xor eax, eax
	jmp short .exit

.error:
	mov bl, ah
	xor eax, eax
	mov al, bl

.exit:
%ifdef DEBUG
	mov bx, ax
	TTY_OUT '<'
	TTY_OUT ':'
	TTY_OUT_HEX bl
	TTY_OUT_NL
	mov ax, bx
%endif

	ENTER_PROTECTED

	pop edi
	pop esi
	pop ebx

	pop ebp
	ret


global bios_tty_write
bios_tty_write:
	; conform to x86_64 cdecl
	push ebp
	mov ebp, esp

	push ebx
	push esi
	push edi

	; get arguments
	mov esi, [ebp + 8]
	mov ecx, [ebp + 12]

	; get data segment of pointer
	mov edx, esi
	shr edx, 16
	shl edx, 12

	ENTER_REAL
	cld
	mov ah, 0xe	; teletype output
	xor bh, bh	; page 0
	mov ds, dx
.loop:
	lodsb		; AL = character
	int 0x10
	cmp al, 0xa
	jne .skip
	mov al, 0xd
	int 0x10
.skip:
	dec cx
	jnz .loop
	ENTER_PROTECTED

	pop edi
	pop esi
	pop ebx

	pop ebp
	ret


        %define CR4_PAE (1<<5)
        %define CR4_PGE (1<<7)
        %define CR4_OSFXSR (1<<9)
        %define CR4_OSXMMEXCPT (1<<10)        
        %define CR4_OSXSAVE (1<<18)                
        
global run64        
run64:
        mov eax, cr4     
        or eax, CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE
        mov cr4, eax  

        mov ecx, 0xC0000080 ; EFER MSR.
        
        rdmsr      
        or eax, 1 << 8      ; Set the LM-bit which is the 9th bit (bit 8).
        or eax, 1 << 11     ; NXE - enable no exec flag in page tables
        wrmsr

        pop edx                 ; return
        pop edx                 ; entry

        push eax
        push eax

        mov eax, cr0    
        or eax, 1 << 31 | 1 ; Set the PG-bit and the PM bit 
        and eax, ~4 ; clear the EM bit
        mov cr0, eax
        
        ;; 64 bit compatibility into the proper long mode
        lgdt [GDT64.Pointer]    ; Load the 64-bit global descriptor table.
        jmp GDT64.Code:setup64
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
        .DataAgain: equ $ - GDT64 ; The data descriptor, a copy for sysret
        dw 0         ; Limit (low).
        dw 0         ; Base (low).
        db 0         ; Base (middle)
        db 10010010b ; Access (read/write).
        db 00000000b ; Granularity.
        db 0         ; Base (high).
        
        .Pointer:    ; The GDT-pointer.
        dw $ - GDT64 - 1    ; Limit.
        dw GDT64, 0         ; 64 bit Base.

[BITS 64]
setup64:
        mov ax, GDT64.Data 
        mov ds, ax     
        mov es, ax 
        mov ss, ax
        xor ax, ax
        mov fs, ax     
        mov gs, ax
        mov eax, 0xffffffff
        shl rax, 32
        or rax, rdx
        jmp rax
