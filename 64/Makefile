
all:app
ROOT=..

include $(ROOT)/runtime/Makefile
include $(ROOT)/virtio/Makefile
# put in a proper library build

.c.o:
	cc $(INCLUDES) $< -c

app: $(RUNTIME) $(VIRTIO) app.c
	cc app.c -Wl,"-e_start" -nostdinc -nostdlib $(INCLUDES) $(RUNTIME) -o app

clean:
	rm -f app *.o *~


