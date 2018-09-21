

$(ROOT)/mkfs/mkfs: 
	cd $(ROOT)/mkfs ; make

$(ROOT)/boot/boot: 
	cd $(ROOT)/boot ; make

# can be stripped 1/5 the size
$(ROOT)/stage3/stage3: 
	cd $(ROOT)/stage3 ; make

%.image: %.manifest $(ROOT)/mkfs/mkfs $(ROOT)/stage3/stage3 $(ROOT)/boot/boot %
	$(ROOT)/mkfs/mkfs - $(ROOT) < $< | cat $(ROOT)/boot/boot - > $@



