obj-m += hello.o
KDIR=/lib/modules/`uname -r`/build
PWD=$(shell pwd)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.ko *.mod.* *.o* *.symvers
