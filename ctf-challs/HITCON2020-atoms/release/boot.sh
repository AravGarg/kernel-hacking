#!/bin/bash

qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./initramfs.cpio.gz \
  -nographic \
  -monitor none \
  -cpu qemu64 \
  -append "console=ttyS0 nokaslr panic=-1 softlockup_panic=1" \
  -no-reboot \
  -m 256M \
  -smp cores=2 \
  -s
