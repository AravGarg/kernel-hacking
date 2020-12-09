find . -print0 | cpio --null -ov --format=newc | gzip -9 > initramfs.cpio.gz
rm ../initramfs.cpio.gz
cp initramfs.cpio.gz ../
cd ../
./boot.sh
