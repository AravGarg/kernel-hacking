gcc exploit.c -o exploit -ggdb -static
find . -print0 | cpio --null -ov --format=newc | gzip -9 > core.cpio
cp core.cpio ../
cd ../
./boot.sh
