

stage3/image:
	cd stage3 ; make image

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	cd net ; make clean
	rm -f runtime/closure_templates.h runtime/contgen

run: stage3/image
	- qemu-system-x86_64  -nographic -drive file=stage3/image,format=raw -m 2G -device isa-debug-exit

