#!/bin/bash

qemu-system-x86_64 \
-initrd ./core.cpio \
-kernel ./bzImage \
-append 'console=ttyS0 root=/dev/ram rw oops=panic panic=1 kaslr' \
-monitor /dev/null \
-m 1024M \
--nographic  \
-s 
