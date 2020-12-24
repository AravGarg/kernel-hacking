obj-m += cmod.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}
all:
	make -C /home/arav/Desktop/kernel-hacking/ctf-challs/SecurityFest2019-brainf64/linux-4.18.16 M=$(PWD) modules EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	make -C /home/arav/Desktop/kernel-hacking/ctf-challs/SecurityFest2019-brainf64/linux-4.18.16 M=$(PWD) clean
	
