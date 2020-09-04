#include<linux/init.h>
#include<linux/module.h>
#include<linux/sched.h>
#include<asm/current.h>

MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void){
	printk(KERN_DEBUG "Hello World.\n");
	return 0;
}
static void hello_exit(void){
	printk(KERN_DEBUG "Goodbye.\n");
}
module_init(hello_init);
module_exit(hello_exit);
