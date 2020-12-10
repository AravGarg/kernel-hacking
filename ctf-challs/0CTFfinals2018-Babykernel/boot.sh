#!/bin/bash

qemu-system-x86_64 \
-initrd ./core.cpio \
-kernel ./bzImage \
-append 'root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr' \
-monitor /dev/null \
-m 1024M \
--nographic \
-smp 2,cores=2,threads=1 \
-s

#-cpu qemu64 \
#-enable-kvm  

#-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
