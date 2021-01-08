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
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/r2con2020-ctfkernel/fs/exploit.c#L1

# general tips
to find offsets with the task struct, first find comm, which is the name of the process, cred struct is just before that. To find next/prev, look for this pattern:
```0xffff8c459e96f310:	0x0000000000000000	0x0000000000000001
0xffff8c459e96f320:	0x0000000000000001	0x000000000000000b
0xffff8c459e96f330:	0x00000000000623f7	0x00000001b629c075
0xffff8c459e96f340:	0x0000000000000000	0xffffffffbae0fa08
0xffff8c459e96f350:	0xffff8c459e96da48	0x000000000000008c
```

if kaslr is off/stack leak, then gs value is fixed, leak with a kernel panic, current_task_struct is at fixed offset from gs, get this from disassembly of _do_fork function. struct cred is at a fixed offset from the struct current_task_struct, get this by `p &(((struct task_struct*)0)->cred)`. Now we have address of struct cred. Overwrite this address to get root.

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

## set_affinity
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/CISC2017-BabyDriver/babydriver/fs/solve.c#L107 

## ropchains
### x64 and x86(change r to e)
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c#L183

https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/xploit.c#L173

https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/asisctf2020-sharedhouse/shared_distfiles/fs/exploit.c#L196

### x86
https://github.com/AravGarg/rootme-myexploits/blob/main/LinKern_x86/basicROP/fs/exploit.c#L49

## leaks in kernel:
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/0CTFfinals2018-Babykernel/fs/exploit.c#L44

if lseek fails:
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/BsidestlvCTF2020-kapara/exploit.c#L62

## set_affinity: 
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/CISC2017-BabyDriver/babydriver/fs/solve.c#L107

## modprobe_path
https://github.com/AravGarg/rootme-myexploits/blob/main/LinKern_x64/SLUB_offby1/fs/exploit.c#L66

## overwrite current process creds with arw:
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/r2con2020-ctfkernel/fs/exploit.c#L265 

https://devcraft.io/2019/01/22/1118daysober-insomnihack-teaser-2019.html

root-me: SLUB off-by-one writeup

https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/BsidestlvCTF2020-kapara/exploit.c#L106

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
https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#subprocess_info
## any-size(msg_msg):
https://ptr-yudai.hatenablog.com/entry/2020/07/06/000622#354pts-Shared-House-7-solves

setxattr("/tmp","x",data,size,XATTR_CREATE)

## kmalloc-32(0x20)
https://github.com/AravGarg/kernel-hacking/blob/master/ctf-challs/secconctf2020-kstack/fs/exploit.c#L174

make sure to have a valid fd in the cache

## kmalloc-128(0x80)
https://github.com/AravGarg/rootme-myexploits/blob/main/LinKern_x64/SLUB_offby1/fs/exploit.c#L86


# Race conditions:
## create new thread:
        pthread_t t1;
        pthread_create(&t1,NULL,startfunc,&arg);
## wait for thread to terminate:
	pthread_join(t1,NULL);
## create new child process that behaves like a thread:
	pid_t pid=clone(startfunc,fakestack+0xf000,CLONE_VM|CLONE_FILES|SIGCHLD,&arg);
## wait for child process to terminate:
	wait(NULL);
## check rootme reentrant-code for race conditions example

# kmalloc flags:
## kmalloc(DMA):
	1
## kmalloc(KERNEL):
	0x6000c0
## kzalloc(KERNEL):
	0x6080c0
