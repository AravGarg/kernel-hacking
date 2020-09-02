obj-m += hello.o
KDIR=/usr/src/linux-headers-4.15.0-107-generic

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order 
