SCRATCH_BASE equ 0x2000
REAL_SP equ SCRATCH_BASE-0x10

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
	jmp gdt32.code16:%%prot16	; enter 16-bit protected mode

%%prot16:
	bits 16
	mov ax, gdt32.data16
	mov ss, ax			; 16-bit stack
	mov ds, ax
	mov es, ax
	mov fs, ax
	mov gs, ax

	;; change the processor mode flag
	mov eax, cr0
	and eax, ~1
	mov cr0, eax			; enter real mode
	jmp 0:%%real

%%real:
	xor ax, ax
	mov ss, ax
	mov ds, ax
	mov es, ax
	mov fs, ax
	mov gs, ax

	mov sp, REAL_SP
%endmacro

%macro ENTER_PROTECTED 0
	lgdt [gdt32.desc]

	;; change the processor mode flag
	mov eax, cr0
	or eax, 1
	mov cr0, eax
	jmp gdt32.code32:%%protected

%%protected:
	bits 32
	mov ax, gdt32.data32
	mov ss, ax
	mov ds, ax
	mov es, ax
	mov fs, ax
	mov gs, ax

	mov esp, [protected_esp]
%endmacro

;; entry point
        extern centry
        section .start

global _start
_start:
	bits 16
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

protected_esp:
	dd REAL_SP			; initial stack pointer


dap:
	db 0x10
	db 0
	.sectors:	dw 0
	.offset:	dw SCRATCH_BASE
	.segment:	dw 0
	.sector:	dd 0
	.sectorm:	dd 0


global bios_read_sectors
bios_read_sectors:
	; conform to x86 cdecl
	push ebp
	mov ebp, esp

	push ebx
	push esi
	push edi

	; save protected mode stack
	mov [protected_esp], esp

	; prepare dap
	mov eax, [ebp + 8]
	mov [dap.sector], eax
	mov eax, [ebp + 12]
	mov [dap.sectors], ax

	ENTER_REAL
	mov si, dap
	mov ah, 0x42
	mov dl, 0x80			; first drive
	int 0x13
	ENTER_PROTECTED

	pop edi
	pop esi
	pop ebx

	pop ebp
	ret


global bios_tty_out
bios_tty_out:
	; conform to x86_64 cdecl
	push ebp
	mov ebp, esp

	push ebx
	push esi
	push edi

	; save protected mode stack
	mov [protected_esp], esp

	; save character
	mov ebx, [ebp + 8]

	ENTER_REAL
	mov ax, bx	; character
	mov ah, 0xe	; teletype output
	xor bh, bh	; page 0
	int 0x10
	ENTER_PROTECTED

	pop edi
	pop esi
	pop ebx

	pop ebp
	ret


global run64        
run64:
        mov eax, cr4     
        or eax, 1 << 5     ;  PAE
        or eax, 1 << 9     ;  osfxsr
        or eax, 1 << 10    ;  osxmmexcpt
;        or eax, 1 << 18    ;  OSXSAVE - faults on kvm
        
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

        
setup64:
        mov ax, GDT64.Data 
        mov ds, ax     
        mov es, ax 
        mov fs, ax     
        mov gs, ax    
        mov ss, ax 
        jmp edx
