	.globl _start
_start:
	adrp	x0, stack_top
	mov	sp, x0
	bl	main
