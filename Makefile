all: examples/hw.image test

force:

ROOT = .

net/lwip:
	(cd $(ROOT)/net; git clone http://git.savannah.nongnu.org/git/lwip.git ; cd lwip ; git checkout STABLE-2_0_3_RELEASE)

test: force
	cd test ; make

unit-test: test
	cd test ; make unit-test

distclean: clean
	rm -rf net/lwip

clean:
	cd boot ; make clean
	cd stage3 ; make clean
	cd mkfs ; make clean
	cd test ; make clean
	cd examples ; make clean
	rm -f runtime/closure_templates.h runtime/contgen image fs

DEBUG ?= n
ifeq ($(DEBUG),y)
	DEBUG_ := -s
else
	DEBUG_ :=
endif

force: 

# boot/boot stage3/stage3 mkfs/mkfs
examples/%.image: force
	cd examples ; make $(notdir $@)

run: rqemu examples/webg.image
	./rqemu -kvm examples/hw.image

run-nokvm: rqemu examples/webg.image
	./rqemu examples/hw.image
