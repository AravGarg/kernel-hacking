obj-m += cmod.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}
KDIR=/home/arav/Desktop/kernel-hacking/ctf-challs/mycustom/linux-4.19.98
all:
	make -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	make -C $(KDIR) M=$(PWD) clean
	
