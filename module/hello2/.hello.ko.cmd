cmd_/media/sf_kalishared/kernel-hacking/module/hello2/hello.ko := ld -r -m elf_x86_64 -z max-page-size=0x200000 -T ./scripts/module-common.lds --build-id  -o /media/sf_kalishared/kernel-hacking/module/hello2/hello.ko /media/sf_kalishared/kernel-hacking/module/hello2/hello.o /media/sf_kalishared/kernel-hacking/module/hello2/hello.mod.o ;  true
