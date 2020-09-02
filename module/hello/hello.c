#include<linux/init.h>// initialize the module
#include<linux/module.h> // to recoginze this as a module

static int test_init(void){
	printk(KERN_ALERT "Hello World\n");//prints to a log file
	return 0;
}

static void test_exit(void){
	printk(KERN_ALERT "Goodbye\n");
}

module_init(test_init);// to tell the module to start execution here
module_exit(test_exit);// to tell the module to end with this function
