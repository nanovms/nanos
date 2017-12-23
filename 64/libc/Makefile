crt0.o: crt0.s
	nasm -felf64 $< -o $@

LIB = crt0.o lib.o serial.o

clean:
	rm -f *~

