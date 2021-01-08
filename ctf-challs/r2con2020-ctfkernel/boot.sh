#!/bin/sh

qemu-system-x86_64 \
	-kernel ./bzImage \
	-initrd ./initramfs \
	-cpu Broadwell \
	-nographic \
	-monitor /dev/null \
	-append "console=ttyS0 quiet" \
	-m 512 \
	-s
