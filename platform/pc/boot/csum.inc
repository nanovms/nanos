csum:
	xor eax, eax
.loop:
	add eax, [si]
	add si, 4
	sub cx, 4
	jnz .loop
	ret
