#!/bin/sh
gcc exploit.c -o exploit -ggdb -static -pthread
find . -print0 | cpio --null -ov --format=newc | gzip -9 > initramfs.gz
cd ../
rm initramfs
cp fs/initramfs.gz .
gunzip initramfs.gz
./boot.sh

