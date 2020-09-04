#include<linux/module.h>
#include<linux/init.h>
#include<linux/moduleparam.h>

MODULE_LICENSE("Dual BSD/GPL");

static int howmany=1;
static int i=0;
static char *whom="World";
module_param(howmany,int,S_IRUGO);
module_param(whom,charp,S_IRUGO);

static int __init my_init(void){
	for(i=0;i<howmany;i++){
		printk(KERN_DEBUG "Hello,%s\n",whom);
	}
	return 0;
}

static void __exit my_exit(void){
	printk(KERN_DEBUG "Goodbye.\n");
}
module_init(my_init);
module_exit(my_exit);

