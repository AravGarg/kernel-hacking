#include<linux/init.h>
#include<linux/module.h>
#include<linux/sched.h>
#include<linux/vermagic.h>
#include<linux/version.h>

MODULE_LICENSE("Dual BSD/GPL");

static int __init hello_init(void){
	printk(KERN_DEBUG "Hello World.\n");
	printk(KERN_DEBUG "executable=%s pid=%d\n",current->comm,current->pid);
	printk(KERN_DEBUG "LINUX_VERSION_CODE=%p\n",LINUX_VERSION_CODE);
	return 0;
}
static void __exit hello_exit(void){
	printk(KERN_DEBUG "Goodbye.\n");
	printk(KERN_DEBUG "executable=%s pid=%d\n",current->comm,current->pid);
}
module_init(hello_init);
module_exit(hello_exit);
