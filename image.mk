

$(ROOT)/mkfs/mkfs: 
	cd $(ROOT)/mkfs ; make

$(ROOT)/boot/boot: 
	cd $(ROOT)/boot ; make

$(ROOT)/stage3/stage3: 
	cd $(ROOT)/stage3 ; make

%.image: %.manifest $(ROOT)/mkfs/mkfs $(ROOT)/stage3/stage3 %
	$(ROOT)/mkfs/mkfs - $(ROOT) < $< | cat $(ROOT)/boot/boot - > $@



