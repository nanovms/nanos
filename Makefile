all: bootable.vdi
# temporarily just load stages 2 and 3 in a single 4k page
STAGE2SIZE = 2048
force:
bootable: 16/stage1 b32.pad 64/app
	cat 16/stage1 b32.pad 64/app > bootable

b32.pad: 32/b32
	dd if=$< of=$@ bs=$(STAGE2SIZE) conv=sync

# does it really have to be a meg?
bootable.pad: bootable
	dd if=$< of=$@ bs=1048576 conv=sync

bootable.vdi: bootable.pad
	rm -f bootable.vdi
	VBoxManage convertdd $< $@ --format VDI

16/stage1: force
	cd 16 ; make stage1 STAGE2SIZE=$(STAGE2SIZE)

32/b32: force
	cd 32 ; make

64/app: force
	cd 64 ; make 

clean:
	cd 16 ; make clean
	cd 32 ; make clean
	cd 64 ; make clean
	rm -f *.raw *.pad *.vdi bootable

# pretty ugly
stop:
	VBoxManage controlvm ugli poweroff
	sleep 3
	VBoxManage storageattach ugli --storagectl "ugli controller"  --port 0 --medium none
	VBoxManage closemedium disk `VBoxManage list hdds  | grep ^UUID | tail -1 | sed -e "s/UUID: *//"`

start:
	VBoxManage storageattach ugli --storagectl "ugli controller" --port 0 --device 0 --type hdd --medium bootable.vdi
	VBoxManage startvm ugli
	sleep 3
	cat /tmp/ugli
