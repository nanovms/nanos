	 
	
;;; apparently this is the preferred technique to zero
;;; a register in x86
%macro zero 1
	xor %1,%1
%endmacro	


;;;   we start up at 7c00 in 16 bit mode
init:		
	bits 16			 
	org 0x00
	bseg equ 0x7c0
	base equ 0x7c00
	stage2 equ 0x8000        

	;; set up our data segment
	mov ax,bseg		
	mov ds,ax
	cli
	
	;; setting a20 allows us to address all of 'extended' memory
	call seta20

        ;; xxx - can trim  
	;; serial setup - [TUP]:page 568
	mov ah,0
	mov al,0xe3  		; 9600 baud, 8N1
	mov dx,0
	int 0x14

	call e820
	add eax,0x100000
	mov [entries.memorymax], eax

        mov ax, stage2 >> 4
        mov cl, 2
        call readsector
	jmp ascend

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; memory detection code:                 ;;;
;;;  this uses the e820 gate to get a set  ;;;
;;;  of regions from the bios. older probe ;;;
;;;  methods are not supported. we only    ;;;
;;;  look for the single region starting   ;;;
;;;  at 0x100000.                          ;;;
;;;  this code derived from a C version    ;;;
;;;  in BSD. no specification is available.;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	
	smapsig equ 0x534D4150
;;; e820 - return the amount of total memory
e820:	zero ebx
.each:	
	mov edx,smapsig
	mov ax,bseg
	mov es,ax
	mov eax,0xe820
	mov edi,.desc
	mov ecx,.end-.desc
	int 0x15
	;; should check that the high bits are zero
	mov ecx,[.base]
	cmp ecx,0x100000
	je .done
	
	cmp ebx,0
	jne .each
	mov eax,0
	ret
	;; fails to account for more than 4GB
.done:	mov eax,[.length]
	ret
	
.desc:	
	.base dd 0,0
	.length dd 0,0
	.type dd 0
.end:

		
;;; seta20 - canned function to open up 'extended memory'
seta20: 
	in al,0x64			; Get status
	test al,0x2			; Busy?
	jnz seta20			; Yes
	mov al,0xd1			; Command: Write
	out 0x64,al			;  output port
.loop:
	in al,0x64			; Get status
	test al,0x2			; Busy?
	jnz .loop			; Yes
	mov al,0xdf			; Enable
	out 0x60,al			;  A20
	ret				; To caller

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
;;; global descriptor table ;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
gdt:
	dw 0,0,0,0                    ;  trash
	dw 0xffff,0,0x9a00,0xcf       ;  32 bit code
	dw 0xffff,0,0x9200,0xcf       ;  32 bit data
	dw 0xffff,0,0x9a00,0x0        ;  16 bit code
	dw 0xffff,0,0x9200,0x0        ;  16 bit data	
.end:
	
gdtdesc: dw gdt.end-gdt-1
	 dd gdt+base

;;; symbolic labels for indices into the GDT representing
;;; segments of interest (reference intel manual)
code32 equ 0x8
data32 equ 0x10
code16 equ 0x18
data16 equ 0x20

;;; enter 32 bit mode from 16 bit mode
;;;  we had the interrupt handlers here..but they dont need to
;;;  be in the mbr
;;;  parameterize entry
ascend:
	lgdt [gdtdesc]

	;; change the processor mode flag
	mov eax, cr0
        or eax, 1
	mov cr0, eax
	jmp code32:stage2
	

;; mov cl, 0x0  ;; sector number ((x-1)/512)
;; target address is ax << 4
        
readsector:
	mov es, ax 
        mov bx, 0    ; target address completely in the segment
        mov ah, 0x2  ; command code
        mov al, 0x18 ;sector count - three pages right now, one for stages 2 and 2 for 3 - fix
        mov dl, 0x80 ; drive is hd0
        mov dh, 0x0  ; head number what the hell
        mov ch, 0x0  ; cyl/track?
        int 0x13
        ret

serial_out:   
       	mov ah,0xe
	mov dx,0
	mov ah,1
	int 0x14
        ret
        

;;  would be nice to derive this
        times 512-2-4 - ($-$$) db 0           
;;;  entries start
entries:
.memorymax:       dd 0
.end:        
;;  mbr signature        
        dw 0xAA55             

        
        
