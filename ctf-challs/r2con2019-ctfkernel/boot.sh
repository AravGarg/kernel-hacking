#!/bin/sh

qemu-system-x86_64 \
	-cpu qemu64,-smep,-smap \
	-m 512 \
	-kernel ./bzImage \
	-nographic \
	-append "console=ttyS0 quiet kaslr" \
	-initrd ./initramfs \
	-monitor /dev/null \
	-s
