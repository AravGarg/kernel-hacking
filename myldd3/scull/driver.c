#include<linux/init.h>
#include<linux/module.h>
#include<linux/types.h>//dev_t structure
#include<linux/kdev_t.h>//macros to extract major and minor numbers from dev_t
#include<linux/fs.h>//functions to obtain device numbers and other file operations
#include<moduleparam.h>//paramaters
#include<linux/scull.h>
#include<linux/cdev.h>//device registration,etc
#include<linux/kernel.h>//container_of macro
#include<asm/uaccess.h>//user_kernel interaction

MODULE_LICENSE("Dual BSD/GPL");
struct dev_t dev=0;
int majorno=0;
int option=0;
int err=0;
//get static(0) or dynamic(1) option from user, and major number(used only if static option is selected)
module_param(option,int,S_IRUGO);//register the parameters
module_param(majorno,int,S_IRUGO);

#define DEVICE_NAME "aravdevice" //name of device
#define COUNT 1 //default number of devices requested,change this if you want something else
#define MINORNO 0 //default start minor number,change this if you want something else
//scull device structure
struct scull_dev{
	struct scull_qset *data;  // Pointer to first quantum set
        int quantum; //the current quantum set
        int qset; //the current array size
        unsigned long size; //amount of data stored here
        unsigned int access_key;  // used by sculluid and scullpriv 
        struct semaphore sem;     // mutual exclusion semaphore     
        struct cdev mcdev;     // Char device structure      
};
struct scull_dev *my_scull_dev;// scull device 
//file operations structure
struct file_operations scull_fops{
	.owner= THIS_MODULE,
	.llseek=scull_llseek,
	.read=scull_read,
	.write=scull_write,
	.ioctl=scull_ioctl,
	.open=scull_open,
	.release=scull_release,
};

int *scull_open(struct inode *inode, struct file *filp){
	filp->private_data=container_of(,inode->cdev,struct scull_dev,cdev);//store corresponding scull_dev structure from inode's cdev.
}
int *scull_release(struct inode *inode,struct file *filp){
	return 0;
}

//helper function to initialize and register device.
static void scull_setup_cdev(struct scull_dev *dev,struct dev_t dev){
	err=cdev_init(&dev->cdev,&scull_fops);//setup the cdev structure
	if(err<0){
		printk(KERN_ALERT "ERROR %d: Failed to setup cdevice.\n");
		return err;
	}
	dev->cdev.ops=&scull_fops;//set the fields of cdev structure
	dev->cdev.owner=THIS_MODULE;
	err=cdev_add(&dev->cdev,dev,COUNT);//register cdev 
	if(err<0){
		printk(KERN_ALERT "ERROR %d: Failed to register cdevice.\n");
		return err;
	}
}

static int __init my_init(){
	//if static major number option selected by user.
	if(option==0){
		dev=MKDEV(majorno,MINORNO);//make dev_t struct from major and minor number
		err=register_chrdev_region(dev,COUNT,DEVICE_NAME);//obtain static major/minor numbers
	}
	//dynamic allocation of major number.
	else{
		err=alloc_chrdev_region(&dev,MINORNO,COUNT,DEVICE_NAME);//obtain dynamic major number
	}
	if(err<0){
		printk(KERN_ALERT "ERROR %d: Failed to obtain major/minor numbers.\n",err);
		return err;
	}
	majorno=MAJOR(dev);//extract major number
	scull_setup_cdev(my_scull_dev,dev);//register cdev	

	
}
static void __exit my_exit(){
	cdev_del(my_scull_dev->cdev);
	unregister_chrdev_region(dev,COUNT);
	printk(KERN_DEBUG "Cleanup done!!!!\n");
}


