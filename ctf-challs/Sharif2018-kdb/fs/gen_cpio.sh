#!/bin/sh
gcc exploit.c -o exploit -ggdb -static -pthread
find . -print0 | cpio --null -ov --format=newc | gzip -9 > rootfs.cpio.gz
cd ../
rm rootfs.cpio
cp fs/rootfs.cpio.gz .
gunzip rootfs.cpio.gz
./boot.sh

