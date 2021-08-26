#!/bin/sh
qemu-system-x86_64 \
    -m 512M \
    -kernel ./bzImageold \
    -initrd ./rootfs.cpio \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr" \
    -cpu kvm64,+smep \
    -monitor /dev/null \
    -nographic \
    -s
