force:

$(ROOT)/mkfs/mkfs: force
	cd $(ROOT)/mkfs ; make

$(ROOT)/boot/boot: force
	cd $(ROOT)/boot ; make

$(ROOT)/stage3/stage3: force
	cd $(ROOT)/stage3 ; make

%.image: %.manifest $(ROOT)/mkfs/mkfs $(ROOT)/stage3/stage3 $(ROOT)/boot/boot %
	$(ROOT)/mkfs/mkfs - $(ROOT) < $< | cat $(ROOT)/boot/boot - > $@



