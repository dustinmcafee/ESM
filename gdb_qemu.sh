#!/bin/bash
gdb \
    -ex "file /home/dustin/AOSP/workingdir/Android_Source_Nougat/kernel/goldfish-3.10-n-dev/vmlinux" \
    -ex 'set arch i386:x86-64:intel' \
    -ex 'target remote localhost:1234' \
    -ex 'hbreak start_kernel'
#    -ex continue \
#    -ex disconnect \
#    -ex set arch i386:x86-64 \
#    -ex target remote localhost:1234
