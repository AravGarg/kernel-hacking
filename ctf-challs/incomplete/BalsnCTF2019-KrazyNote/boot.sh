#!/bin/bash

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel ./bzImage \
    -append 'console=ttyS0 oops=panic panic=1 nokaslr' \
    -monitor /dev/null \
    -initrd ./core.cpio  \
    -smp cores=2,threads=2 \
    -cpu kvm64,smep,smap \
    -s
