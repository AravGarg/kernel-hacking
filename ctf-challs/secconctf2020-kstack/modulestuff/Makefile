obj-m+=kstack.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}
KDIR=/home/arav/Desktop/kernel-hacking/ctf-challs/secconctf2020-kstack/linux-4.19.98
all:
	make -C $(KDIR) M=$(PWD) modules EXTRA_FLAGS="$(MY_CFLAGS)"
	cp kstack.ko /media/sf_kalishared
	cp kstack.ko /home/arav/Desktop/kernel-hacking/ctf-challs/secconctf2020-kstack/fs/root
clean:
	make -C $(KDIR) M=$(PWD) clean
