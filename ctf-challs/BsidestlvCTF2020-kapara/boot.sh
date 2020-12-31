#!/bin/bash

qemu=(
    qemu-system-x86_64
    -kernel ./bzImage
    -m 2048
    -boot order=nc
    -watchdog i6300esb
    -rtc base=localtime
    -hda rootfsback.ssh
    -device e1000,netdev=net0
    -netdev user,id=net0,hostfwd=tcp::5555-:22
    -nographic
    -no-reboot
    -s
)

append=(
    hung_task_panic=1
    earlyprintk=ttyS0,115200
    debug
    apic=debug
    sysrq_always_enabled
    rcupdate.rcu_cpu_stall_timeout=100
    panic=-1
    softlockup_panic=1
    nmi_watchdog=panic
    load_ramdisk=2
    prompt_ramdisk=0
    console=tty0
    console=ttyS0,115200
    root=/dev/sda rw 
    drbd.minor_count=8
    nokaslr
)

"${qemu[@]}" --append "${append[*]}"
