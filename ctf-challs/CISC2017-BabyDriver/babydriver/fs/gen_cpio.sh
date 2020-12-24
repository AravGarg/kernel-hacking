find . -print0 | cpio --null -ov --format=newc | gzip -9 > rootfs.cpio
rm ../rootfs.cpio
cp rootfs.cpio ../
cd ../
./boot.sh
