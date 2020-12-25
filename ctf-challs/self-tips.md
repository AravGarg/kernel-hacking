# general setup
## decompress filesystem
cp ../core.cpio core.cpio.gz #  copy the gzip file into the folder and change the suffix 

gunzip ./core.cpio.gz 

cpio -idm < ./core.cpio
# if file system is already .gz with file type gzip
gzip -cd ../initramfs.cpio.gz | cpio -imd --quiet

#for a ext2/3/4 filesystem
mount it on the host while qemu is off, make changes, unmount then boot qemu.

mount -o loop,offset=offset /path/to/disk_image /mnt/mount_point

https://access.redhat.com/solutions/24029

# gencpio.sh
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/gen_cpio.sh

# attach.sh
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/attach.sh

# compile.sh
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/compile.sh

# cmd
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/cmd

# include
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c

# general tips
setsid to 0 to get root->

to access /sys/module/name_of_module/sections/.text for address of .text section of module

/proc/kallsyms for all symbols.

change uid to 0 in /etc/passwd

use cpu kvm64 to allow smep,smap

/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux bzImage > vmlinux

cat /sys/module/name_of_module/sections/.text->address of .text sectiion of loaded module.

load debug info:add-symbol-file /path/to/module textaddrbase

open the dev file created in /dev or /proc or /sys to interact with the kernel module.

if you obtain major number with register_chrdev(), you need to manually make the device file.

proc_create automatically creates the device file in /proc

# code snippets:
## define kernel functions:
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c#L23

## privesc:
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c#L59 

## save_state
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c#L62

## getshell
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c#L75

## ropchains
### x64 and x86(change r to e)
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c#L183

https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/xploit.c#L173

### x86
https://github.com/AravGarg/rootme-myexploits/blob/main/LinKern_x86/basicROP/fs/exploit.c#L49

## leaks in kernel:
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/0CTFfinals2018-Babykernel/fs/exploit.c#L44

## set_affinity: 
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/CISC2017-BabyDriver/babydriver/fs/solve.c#L107

## modprobe_path
https://github.com/AravGarg/rootme-myexploits/blob/main/LinKern_x64/SLUB_offby1/fs/exploit.c#L66

## overwrite current process creds with arw:
1 https://devcraft.io/2019/01/22/1118daysober-insomnihack-teaser-2019.html

2 root-me: SLUB off-by-one writeup

## nullptr deference
### for x64:
https://github.com/AravGarg/rootme-myexploits/blob/main/LinKern_x64/racecondition/exploit.c#L25

### for x86:
https://github.com/AravGarg/rootme-myexploits/blob/main/LinKern_x86/nullptr_dereference/fs/exploit.c#L25

## prepareUFD
https://github.com/pr0cf5/CTF-writeups/blob/master/2019/BalsnCTF/knote/exploit.c#L147

## handle page-fault
https://github.com/pr0cf5/CTF-writeups/blob/master/2019/BalsnCTF/knote/exploit.c#L246

# kernel ds + sprays

## kmalloc-32 spray:open("/proc/self/stat",O_RDONLY)

## kmalloc-1024 tty_struct open("/dev/ptmx")

## kmalloc-128 cred_struct fork()


# Race conditions:
## create new thread:
        pthread_t t1;
        pthread_create(&t1,NULL,startfunc,&arg);
# wait for thread to terminate:
	pthread_join(t1,NULL);
# create new child process that behaves like a thread:
	pid_t pid=clone(startfunc,fakestack+0xf000,CLONE_VM|CLONE_FILES|SIGCHLD,&arg);
# wait for child process to terminate:
	wait(NULL);
# check rootme reentrant-code for race conditions example


