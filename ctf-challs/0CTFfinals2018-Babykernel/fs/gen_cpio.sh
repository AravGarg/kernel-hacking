#!/bin/sh
find . -print0 | cpio --null -ov --format=newc | gzip -9 > core.cpio
cd ../
rm core.cpio
cp fs/core.cpio .
./boot.sh


