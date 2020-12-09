find . -print0 | cpio --null -ov --format=newc | gzip -9 > core.cpio
rm ../core.cpio
cp core.cpio ../
cd ../
./boot.sh
