#include<linux/init.h>
#include<linux/module.h>
#include<linux/sched.h>
#include<linux/vermagic.h>
#include<linux/moduleparam.h>
MODULE_LICENSE("Dual BSD/GPL");

static int __init hello_init(void)
{
	printk(KERN_ALERT "Hello World\n");
	printk(KERN_ALERT "invocing executable=%s, pid=%d.\n",current->comm,current->pid);
	printk(KERN_ALERT "%s.\n",UTS_RELEASE);
	return 0;
}
static void __exit hello_exit(void)
{
	printk(KERN_ALERT "Goodbye\n");
	printk(KERN_ALERT "invocing executable=%s, pid=%d.\n",current->comm,current->pid);
}
module_init(hello_init);
module_exit(hello_exit);
