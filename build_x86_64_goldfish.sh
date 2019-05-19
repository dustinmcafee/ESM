#!/bin/bash
#../prebuilts/qemu-kernel/build-kernel.sh --arch=x86_64 --cross=x86_64-linux-android- --config=x86_64 --verbose --out=/home/dustin/AOSP/build_out/Android_Source/target/product/generic_x86_64/ -j8
../../prebuilts/qemu-kernel/build-kernel.sh --arch=x86_64 --cross=x86_64-linux-android- --config=x86_64_ranchu --verbose --out=/home/dustin/Android/Sdk/system-images/android-25/google_apis/x86_64 -j8
