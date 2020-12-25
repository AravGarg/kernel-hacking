#!/bin/sh
#gcc exploit.c -o exploit -ggdb -static -pthread
find . -print0 | cpio --null -ov --format=newc | gzip -9 > rootfs.cpio
cd ../
rm rootfs.cpio
cp fs/rootfs.cpio .
./boot.sh
