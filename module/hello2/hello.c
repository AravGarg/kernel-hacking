#include<linux/init.h>
#include<linux/module.h>
#include<linux/moduleparam.h>//to enable user arguments
int param_var=0;// variable to store the argument
int pvar[3]={0,0,0};//another variable
module_param(param_var,int,S_IRUSR|S_IWUSR); // register the variable
module_param_array(pvar,int,NULL,S_IRUSR|S_IWUSR); //register the array variable

void display(void){
	printk(KERN_ALERT "pvar=%d\n",pvar[0]);	
	printk(KERN_ALERT "pvar=%d\n",pvar[1]);	
	printk(KERN_ALERT "pvar=%d\n",pvar[2]);	
}
static int hello_init(void){
	printk(KERN_ALERT "Hello World2\n");
	display();
	return 0;
}
static void hello_exit(void){
	printk(KERN_ALERT "Goodbye2\n");
}
module_init(hello_init);
module_exit(hello_exit);


