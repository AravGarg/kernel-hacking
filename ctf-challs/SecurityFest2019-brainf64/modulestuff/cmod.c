#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
 
 
static dev_t first; // Global variable for the first device number
static struct cdev c_dev; // Global variable for the character device structure
static struct class *cl; // Global variable for the device class
char *global_buf;
 
static int cmod_open(struct inode *i, struct file *f){
  printk(KERN_INFO "cmod: open()\n");
  return 0;
}
 
static int cmod_close(struct inode *i, struct file *f)
{
  printk(KERN_INFO "cmod: close()\n");
  return 0;
}
 
static ssize_t cmod_alloc(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  printk(KERN_INFO "cmod: read()\n");
  global_buf=kmalloc(len,GFP_DMA);
  return 0;
}
 
static ssize_t cmod_delete(struct file *f, const char __user *buf,size_t len, loff_t *off)
{
  kfree(global_buf);
  global_buf=NULL;
  return 0; 
}
static struct file_operations pugs_fops =
{
  .owner = THIS_MODULE,
  .open = cmod_open,
  .release = cmod_close,
  .read = cmod_alloc,
  .write = cmod_delete,
};
 
static int __init cmod_init(void) /* Constructor */
{
  printk(KERN_INFO "cmod registered");
  if (alloc_chrdev_region(&first, 0, 8, "cmod") < 0)
  {
    return -1;
  }
  if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)
  {
    unregister_chrdev_region(first, 1);
    return -1;
  }
  if (device_create(cl, NULL, first, NULL, "cmod") == NULL)
  {
    printk(KERN_INFO "cmod error");
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }
  cdev_init(&c_dev, &pugs_fops);
  if (cdev_add(&c_dev, first, 1) == -1)
  {
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }
 
  return 0;
}
 
static void __exit cmod_exit(void) /* Destructor */
{
    printk(KERN_INFO "cmod unregistered");
    unregister_chrdev_region(first, 1);
}
 
module_init(cmod_init);
module_exit(cmod_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arav");
MODULE_DESCRIPTION("Mem management");
