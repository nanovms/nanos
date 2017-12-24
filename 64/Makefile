VPATH = libc ../runtime

all:app

include libc/Makefile

# put in a proper library build
%.o: %.c
	cc -Ilibc -I../runtime $< -c

app: $(LIB) app.c
	cc app.c -Wl,"-e_start" -nostdinc -nostdlib -Ilibc $(LIB) -o app

clean:
	rm -f app *.o *~
	cd libc ; make clean


