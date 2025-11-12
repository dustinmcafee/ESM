# ESM for Android 12 - Quick Start Guide

This guide will walk you through downloading AOSP, applying ESM patches, and building a working Android 12 image with ESM for Google Pixel 5.

## Prerequisites

- Ubuntu 18.04+ (20.04 or 22.04 recommended)
- 16GB+ RAM (32GB recommended)
- 250GB+ free disk space (400GB recommended)
- Fast internet connection

## Time Estimates

- Download AOSP: 2-6 hours
- Apply patches: 5 minutes
- Build (first time): 1-4 hours
- Flash device: 5 minutes

**Total**: 4-10 hours for complete process

---

## Step 1: Set Up Build Environment

### Install Required Packages

```bash
sudo apt-get update
sudo apt-get install -y \
    git-core gnupg flex bison build-essential zip curl zlib1g-dev \
    gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev \
    x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev \
    libxml2-utils xsltproc unzip fontconfig python3 python-is-python3 \
    bc cpio rsync libssl-dev openjdk-11-jdk ccache
```

### Configure Git

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Install Repo Tool

```bash
mkdir -p ~/bin
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo
export PATH=~/bin:$PATH
echo 'export PATH=~/bin:$PATH' >> ~/.bashrc
```

### Set Up ccache (Recommended)

```bash
export USE_CCACHE=1
export CCACHE_DIR=$HOME/.ccache
ccache -M 50G
echo 'export USE_CCACHE=1' >> ~/.bashrc
echo 'export CCACHE_DIR=$HOME/.ccache' >> ~/.bashrc
```

---

## Step 2: Download AOSP Source

### Create Working Directory

```bash
mkdir -p ~/android/aosp_pixel5_esm
cd ~/android/aosp_pixel5_esm
```

### Initialize Repo

```bash
repo init -u https://android.googlesource.com/platform/manifest -b android-12.0.0_r3
```

### Download Source (~80-100 GB, 2-6 hours)

```bash
repo sync -c -j8 --force-sync --no-clone-bundle --no-tags
```

**Tip**: If download fails, just run the same command again to resume.

---

## Step 3: Download Device Binaries

Google Pixel devices require proprietary binaries for full functionality.

```bash
cd ~/android/aosp_pixel5_esm

# Download driver binaries for Pixel 5 (Build ID: SP1A.210812.016.A1)
wget https://dl.google.com/dl/android/aosp/google_devices-redfin-sp1a.210812.016.a1-fe9bc5fb.tgz
wget https://dl.google.com/dl/android/aosp/qcom-redfin-sp1a.210812.016.a1-28a4cf6d.tgz

# Extract binaries
tar -xzf google_devices-redfin-sp1a.210812.016.a1-fe9bc5fb.tgz
tar -xzf qcom-redfin-sp1a.210812.016.a1-28a4cf6d.tgz

# Run extraction scripts (read and accept licenses)
./extract-google_devices-redfin.sh
./extract-qcom-redfin.sh
```

When prompted, read the licenses and type `I ACCEPT` for each.

---

## Step 4: Download Kernel Source

The kernel source is not included in the main AOSP sync. We need to clone it separately.

```bash
cd ~/android/aosp_pixel5_esm

# Clone Pixel 5 kernel (Redbull)
git clone https://android.googlesource.com/kernel/msm kernel_redbull_source

cd kernel_redbull_source

# Checkout the Android 12 branch
git checkout android-msm-redbull-4.19-android12

# Create base branch for patch application
git checkout -b base
```

---

## Step 5: Download and Apply ESM Patches

### Download ESM Patches

Option A: If hosted on GitHub (replace with actual URL):
```bash
cd ~/android
git clone https://github.com/your-username/esm-android12-patches.git esm_patches
cd esm_patches
```

Option B: If you have the patch files locally:
```bash
# Copy the esm patch directory to your home directory
# Ensure you have the following structure:
# ~/esm_patches/
#   ├── patches/
#   │   ├── kernel_redbull.patch
#   │   ├── bionic.patch
#   │   ├── frameworks_native.patch
#   │   ├── frameworks_base.patch
#   │   ├── libcore.patch
#   │   ├── build_make.patch
#   │   └── device_google_redfin.patch
#   └── scripts/
#       └── apply_patches.sh
```

### Run Automated Patch Application

```bash
cd ~/android/aosp_pixel5_esm

# Download and run the patch application script
bash ~/esm_patches/scripts/apply_patches.sh
```

**What this script does**:
1. Applies kernel ESM implementation patch
2. Adds ESM syscalls to bionic
3. Updates InputFlinger to use ESM
4. Modifies framework watchdog for ESM awareness
5. Updates build system configuration

### Manual Patch Application (Alternative)

If you prefer to apply patches manually:

```bash
cd ~/android/aosp_pixel5_esm

# Apply kernel patch
cd kernel_redbull_source
git apply ~/esm_patches/patches/kernel_redbull.patch
git add .
git commit -m "Add ESM support to kernel"
cd ..

# Apply bionic patch
cd bionic
git apply ~/esm_patches/patches/bionic.patch
git add .
git commit -m "Add ESM syscalls to bionic"
cd ..

# Apply frameworks/native patch
cd frameworks/native
git apply ~/esm_patches/patches/frameworks_native.patch
git add .
git commit -m "Integrate ESM with InputFlinger"
cd ..

# Apply frameworks/base patch
cd frameworks/base
git apply ~/esm_patches/patches/frameworks_base.patch
git add .
git commit -m "Add ESM awareness to Watchdog"
cd ..

# Apply libcore patch
cd libcore
git apply ~/esm_patches/patches/libcore.patch
git add .
git commit -m "Add ESM constants to OsConstants"
cd ..

# Apply build/make patch
cd build/make
git apply ~/esm_patches/patches/build_make.patch
git add .
git commit -m "Update build system for ESM kernel"
cd ..

# Apply device config patch
cd device/google/redfin
git apply ~/esm_patches/patches/device_google_redfin.patch
git add .
git commit -m "Configure Pixel 5 for ESM"
cd ..
```

### Verify Patches Applied

```bash
cd ~/android/aosp_pixel5_esm

# Check that files are modified
git -C kernel_redbull_source log --oneline -1
git -C bionic log --oneline -1
git -C frameworks/native log --oneline -1
git -C frameworks/base log --oneline -1
git -C libcore log --oneline -1
git -C build/make log --oneline -1
git -C device/google/redfin log --oneline -1

# Should show your ESM commits
```

---

## Step 6: Build Android with ESM

### Set Up Build Environment

```bash
cd ~/android/aosp_pixel5_esm

# Source the build environment
source build/envsetup.sh

# Select build target (Pixel 5, userdebug variant)
lunch aosp_redfin-userdebug
```

You should see:
```
============================================
PLATFORM_VERSION=12
TARGET_PRODUCT=aosp_redfin
TARGET_BUILD_VARIANT=userdebug
============================================
```

### Option A: Use Provided Build Script (Recommended)

If the ESM patches include `build.sh`:

```bash
cd ~/android/aosp_pixel5_esm

# Build everything (kernel + AOSP)
# This takes 1-4 hours depending on your hardware
time ./build.sh -j$(nproc)
```

### Option B: Manual Build

#### Build Kernel First

```bash
cd ~/android/aosp_pixel5_esm

# Set up environment
export AOSP_ROOT=$(pwd)
export KERNEL_SRC=$AOSP_ROOT/kernel_redbull_source
export KERNEL_OUT=$AOSP_ROOT/out/target/product/redfin/obj/KERNEL_OBJ
export CLANG_PATH=$AOSP_ROOT/prebuilts/clang/host/linux-x86/clang-r416183b

# Create output directory
mkdir -p $KERNEL_OUT

# Configure kernel
make -C $KERNEL_SRC O=$KERNEL_OUT \
    ARCH=arm64 \
    LLVM=1 \
    LLVM_IAS=1 \
    CLANG_TRIPLE=aarch64-linux-gnu- \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
    redbull_defconfig

# Build kernel (takes 3-7 minutes)
make -C $KERNEL_SRC O=$KERNEL_OUT \
    ARCH=arm64 \
    LLVM=1 \
    LLVM_IAS=1 \
    CLANG_TRIPLE=aarch64-linux-gnu- \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
    -j$(nproc) \
    Image.lz4-dtb

echo "Kernel built successfully!"
```

#### Build AOSP

```bash
cd ~/android/aosp_pixel5_esm

# Ensure environment is set
source build/envsetup.sh
lunch aosp_redfin-userdebug

# Start full build (takes 1-4 hours)
time m -j$(nproc)
```

### Monitor Build Progress

In another terminal:
```bash
# Watch build progress
watch -n 5 'tail -20 ~/android/aosp_pixel5_esm/out/.module_paths/Android.bp.list'

# Check system resources
htop

# Check ccache hit rate
ccache -s
```

### Build Complete

When successful, you'll see:
```
#### build completed successfully (01:23:45 (hh:mm:ss)) ####
```

Build outputs are in:
```
out/target/product/redfin/
├── boot.img          # Boot image (kernel + ramdisk)
├── system.img        # System partition
├── vendor.img        # Vendor partition
├── product.img       # Product partition
└── ...
```

---

## Step 7: Flash to Pixel 5

### Prerequisites

#### Unlock Bootloader (ONE TIME ONLY)

**WARNING: This will WIPE YOUR DEVICE!**

```bash
# On device:
# 1. Settings → About Phone → Tap "Build Number" 7 times
# 2. Settings → System → Developer Options → Enable "OEM unlocking"
# 3. Settings → System → Developer Options → Enable "USB debugging"

# On computer:
adb reboot bootloader

# Wait for bootloader mode, then:
fastboot flashing unlock

# Use volume keys to select "Unlock" and press power button
# Device will wipe and reboot
```

### Flash ESM-Enabled Android

```bash
cd ~/android/aosp_pixel5_esm/out/target/product/redfin

# Reboot to bootloader
adb reboot bootloader

# Wait for bootloader mode (screen shows "Start")

# Flash all partitions (-w wipes userdata)
fastboot flashall -w

# Wait for flash to complete (2-3 minutes)
```

### First Boot

- Device will reboot automatically
- First boot takes 2-5 minutes
- Complete Android setup wizard
- ESM is now active!

---

## Step 8: Verify ESM is Working

### Check Kernel Has ESM

```bash
adb shell

# Check kernel version
uname -r
# Should show: 4.19.x with recent build date

# Verify ESM syscalls exist
cat /proc/kallsyms | grep esm
# Should show:
# ffffffc010xxxxx T esm_register
# ffffffc010xxxxx T esm_wait
# ffffffc010xxxxx T esm_ctl
# ffffffc010xxxxx T is_in_esm_wait

# Check kernel log for ESM initialization
dmesg | grep -i esm
```

### Check InputFlinger is Using ESM

```bash
adb logcat | grep -i "esm\|inputflinger"

# You should see ESM-related log messages when touching screen
# Example: "ESM: registered device fd=X inode=Y"
```

### Test Input Works

- Touch the screen - should be responsive
- Type on keyboard
- Use buttons (power, volume)
- Test gestures

Everything should work normally, but with lower latency!

---

## Troubleshooting

### Build Fails: "error: esm_register not declared"

**Cause**: Bionic patch not applied correctly.

**Fix**:
```bash
cd ~/android/aosp_pixel5_esm/bionic
git apply ~/esm_patches/patches/bionic.patch
```

### Build Fails: VLA compilation error

**Cause**: Old version of kernel patch.

**Fix**: Ensure you have the latest `kernel_redbull.patch` that uses `kmalloc()` instead of VLA.

### Kernel Doesn't Have ESM

**Symptom**: `cat /proc/kallsyms | grep esm` returns nothing.

**Cause**: Wrong kernel flashed.

**Fix**: Rebuild kernel separately and reflash boot.img:
```bash
cd ~/android/aosp_pixel5_esm
# Build kernel (see Step 6B)
# Then:
adb reboot bootloader
fastboot flash boot out/target/product/redfin/boot.img
fastboot reboot
```

### Device Bootloops

**Fix**: Flash stock factory image to recover:
```bash
# Download from: https://developers.google.com/android/images
# Extract and run:
./flash-all.sh
```

---

## Next Steps

- Read `docs/ESM_TECHNICAL.md` for detailed technical information
- Read `docs/ARCHITECTURE.md` for code structure
- Experiment with ESM performance using benchmarks
- Contribute improvements!

---

## Quick Reference

```bash
# Download AOSP
repo init -u https://android.googlesource.com/platform/manifest -b android-12.0.0_r3
repo sync -c -j8 --no-tags

# Clone kernel
git clone https://android.googlesource.com/kernel/msm kernel_redbull_source
cd kernel_redbull_source && git checkout android-msm-redbull-4.19-android12

# Apply patches
cd ~/android/aosp_pixel5_esm
bash ~/esm_patches/scripts/apply_patches.sh

# Build
source build/envsetup.sh
lunch aosp_redfin-userdebug
./build.sh -j$(nproc)

# Flash
adb reboot bootloader
fastboot flashall -w

# Verify
adb shell "cat /proc/kallsyms | grep esm"
```

---

## Getting Help

1. Check the full build guide: `ESM_BUILD_HOWTO.md`
2. Read technical docs: `docs/ESM_TECHNICAL.md`
3. Review patch contents in `patches/` directory
4. Check AOSP build documentation: https://source.android.com

**Document Version**: 1.0
**Date**: 2025-11-12
**Tested On**: Ubuntu 22.04 LTS, Google Pixel 5
