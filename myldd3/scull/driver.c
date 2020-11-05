#include<linux/init.h>
#include<linux/module.h>
#include<linux/moduleparam.h>
#include<linux/fs.h>
#include<linux/cdev.h>
#include<linux/kernel.h>
#include<linux/slab.h>
#include<linux/errno.h>
#include<asm/uaccess.h>
#include "scull.h"
dev_t devno;//stores major and minor numbers for the driver and device respectively.
int ret;//check return values
int scull_major=SCULL_MAJOR;//major number
int scull_minor=0;//minor number
int scull_nr_devs=SCULL_NR_DEVS;//number of devices
int scull_quantum=SCULL_QUANTUM;
int scull_qset=SCULL_QSET;
struct scull_dev dev;

int scull_trim(struct scull_dev *dev){
	struct scull_qset *next,*dptr;
	int qset=dev->qset;
	int i;
	for(dptr=dev->data;dptr;dptr=next){
		if(dptr->data){
			for(i=0;i<qset;i++){
				kfree(dptr->data[i]);
			}
			kfree(dptr->data);
			dptr->data=NULL;
		}
		next=dptr->next;
		kfree(dptr);
	}
	dev->size=0;
	dev->quantum=scull_quantum;
	dev->qset=scull_qset;
	dev->data=NULL;
	return 0;
}
struct scull_qset *scull_follow(struct scull_dev *dev,int item){
}
int scull_open(struct inode* inode,struct file *filp){
	struct scull_dev *dev;
	dev=container_of(inode->cdev,struct scull_dev,cdev);
	filp->private_data=dev;
	if((filp->f_flags & O_ACCMODE)==O_WRONLY){
		scull_trim(dev);
	}
	return 0;
}
int scull_release(struct inode* inode,struct file *filp){
	return 0;
}
ssize_t scull_read(struct file *filp, char __user *buff,size_t count,loff_t *offp){
	struct scull_dev *dev=filp->private_data;
	struct scull_qset *dptr;
	int quantum=dev->quantum, qset=dev->qset;
	int itemsize=quantum*qset;
	int item,s_pos,q_pos,rest;
	if(down_interruptible(&dev->sem)){
		return -ERSTARTSYS;
	}
	if(*f_pos>=dev->size){
		goto out;
	}
	if(*f_pos+count>dev->size){
		count=dev->size-*f_pos;
	}
	item=(long)*f_pos/itemsize;
	rest=(long)*f_pos%itemsize;
	s_pos=rest/quantum;
	q_pos=rest%quantum;
	dptr=scull_follow(dev,item);
	if(dptr==NULL || !dptr->data || !dptr->data[s_pos]){
		goto out;
	}
	if(count>quantum-q_pos){
		count=quantum-q_pos;
	}
	if(copy_to_user(buf,dptr->data[s_pos]+q_pos,count)){
		retval=-EFAULT
	}
}

struct file_operations scull_fops={//file operations
        .owner=THIS_MODULE,
        .llseek=scull_llseek,
        .read=scull_read,
        .write=scull_write,
        .ioctl=scull_ioctl,
        .open=scull_open,
        .release=scull_release,
};
module_param(scull_major,int,SIRUGO);
module_param(scull_minor,int,SIRUGO);
module_param(scull_nr_devs,int,SIRUGO);
module_param(scull_quantum,int,SIRUGO);
module_param(scull_qset,int,SIRUGO);
MODULE_LICENSE("Dual BSD/GPL");

static void scull_setup_cdev(struct scull_dev *dev,int index){//device registration
	devno=MKDEV(scull_major,scull_minor+index);
	cdev_init(&dev->cdev,&scull_fops);
	dev->cdev.owner=THIS_MODULE;
	dev->cdev.ops=&scull_fops;
	ret=cdev_add(&dev->cdev,devno,1);
	if(ret){
		printk(KERN_ALERT "scull%d registration failed with error%d\n",index,ret);
	}
}
static void scull_release_cdev(struct scull_dev *dev){//unregister device
	cdev_del(&dev->cdev);
}

static int __init scull_init(void){
	if(scull_major){
		devno=MKDEV(scull_major,scull_minor);
		ret=register_chrdev_region(devno,scull_nr_devs,DEVICE_NAME);
	}
	else{
		ret=alloc_chrdev_region(&devno,scull_minor,scull_nr_devs,DEVICE_NAME);
		scull_major=MAJOR(devno);
	}
	if(ret!=0){
		printk(KERN_ALERT "Failed to allocate major number=%d.\n",scull_major);
		return ret;
	}
	return 0;
}
static void __exit scull_exit(void){
	scull_trim(&dev);
	unregister_chrdev_region(devno,scull_nr_devs);
}
module_init(scull_init);
module_exit(scull_exit);
