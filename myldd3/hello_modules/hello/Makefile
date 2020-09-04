obj-m += hello.o
KDIR=/lib/modules/`uname -r`/build
PWD=$(shell pwd)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	insmod ./*.ko
	dmesg
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
