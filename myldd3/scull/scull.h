#define SCULL_MAJOR 0
#define SCULL_NR_DEVS 4
#define SCULL_QUANTUM 4000
#define SCULL_QSET 1000
struct scull_qset{
        void **data;
        struct scull_qset *next;
};
struct scull_dev{//scull device
        struct scull_qset *data;//pointer to the first quantum set
        int quantum;//the current quantum size
        int qset;//the current array size
        unsigned long size;//amount of data stored here
        unsigned int access_key;//used by sculluid and scullpriv
        struct semaphore sem;//mutual exclusion semaphore
        struct cdev cdev;//char device structure
};
struct file_operations{//file operations
        .owner=THIS_MODULE,
        .llseek=scull_llseek,
        .read=scull_read,
        .write=scull_write,
        .ioctl=scull_ioctl,
        .open=scull_open,
        .release=scull_release,
};
#define DEVICE_NAME "Mysculldevice"

