#! /bin/bash

qemu-system-x86_64 \
-m 1024M \
-cpu max,+smap,+smep,check \
-kernel ./bzImage \
-initrd ./initramfs.cpio.gz  \
-no-reboot \
-nographic \
-monitor /dev/null \
-s \
-smp cores=1,threads=1 \
-append 'console=ttyS0 oops=panic panic=1 nokaslr'





