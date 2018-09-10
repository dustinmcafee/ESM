#!/bin/bash
/usr/bin/gdb \
    -ex "file vmlinux" \
    -ex 'target remote localhost:1234' \
    -ex 'break start_kernel' \
    -ex 'break evdev_event' \
    -ex 'break mousedev_event'
#-ex lx-symbol \
#-ex set debug-file-directory /home/dustin/AOSP/build_out/Android_Source/target/product/generic_x86/symbols/ \

