OBJECT_NAME=slbcore

obj-m += $(OBJECT_NAME).o
slbcore-objs := slbcore_main.o slbcore_util.o checksum/checksum.o

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(dir $(mkfile_path))

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(current_dir) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(current_dir) clean

load:
	insmod $(OBJECT_NAME).ko

unload:
	rmmod $(OBJECT_NAME).ko
	
reload: unload load

info:
	modinfo $(OBJECT_NAME).ko