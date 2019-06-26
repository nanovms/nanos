;;;   we start up at 7c00 in 16 bit mode
init:
	bits 16
	base equ 0x7c00
	org base
	stage2 equ 0x8000        

	;; set up our data segment
	xor ax,ax
	mov ds,ax
	cli
	
	;; setting a20 allows us to address all of 'extended' memory
	call seta20

        ;;  serial setup?
	mov ah,0
	mov al,0xe3  		; 9600 baud, 8N1

	mov dx,0
	int 0x14
        
	call e820

        ;;;  disable 8259
        mov al, 0xff
        out 0xa1, al
        out 0x21, al

        call readsectors
        
	jmp 0:stage2

;;; e820 - return the amount of total memory
e820:	xor ebx, ebx
        mov edi, fsentry
.each:	
	sub edi, fsentry.end - fsentry
	mov edx, 0x534D4150 ; 'SMAP'
	xor ax, ax
	mov es, ax
	mov eax, 0xe820
	mov ecx, fsentry.end - fsentry
	int 0x15
        test ebx, ebx
        jne .each
	ret
        
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


serial_out:   
	mov dx,0
	mov ah,1
	int 0x14
        ret
        

sectorsize equ 512

dap:
        db 0x10
        db 0
        .sectors     dw STAGE2SIZE/sectorsize
        .offset      dw stage2
        .segment     dw 0
        .sector      dd 1
        .sectorm     dd 0
        
readsectors:
        mov si, dap
        mov ah, 0x42
        mov dl, 0x80
        int 0x13
        ret


        times 512 - (end - fsentry) - ($ - $$) db 0

;; tell stage2 what its size on disk is so we can find the filesystem
fsentry:
        dq STAGE1SIZE + STAGE2SIZE
        dq 0
        dd 0x5    ; REGION_FILESYSTEM - defined in src/x86_64/region.h
.end:

;;  mbr partition entries
part1:   times 16 db 0
part2:   times 16 db 0
part3:   times 16 db 0
part4:   times 16 db 0
;;  mbr signature
        dw 0xAA55
end:
