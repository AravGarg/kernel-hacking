#!/bin/sh
gcc exploit.c -o exploit -ggdb -static -pthread
find . -print0 | cpio --null -ov --format=newc | gzip -9 > initramfs.cpio.gz
cd ../
rm initramfs.cpio.gz
cp fs/initramfs.cpio.gz .
./boot.sh
