#include<linux/init.h>
#include<linux/module.h>
#include<linux/sched.h>

MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void){
	printk(KERN_DEBUG "Hello World.\n");
	printk(KERN_INFO "Process is \"%s\", pid=%d.\n",current->comm,current->pid);
	return 0;
}
static void hello_exit(void){
	printk(KERN_DEBUG "Goodbye.\n");
	printk(KERN_INFO "Process is \"%s\", pid=%d.\n",current->comm,current->pid);
}
module_init(hello_init);
module_exit(hello_exit);
