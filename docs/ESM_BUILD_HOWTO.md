# How to Build Android 12 with ESM for Google Pixel 5

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Setting Up the Build Environment](#setting-up-the-build-environment)
4. [Downloading AOSP Source Code](#downloading-aosp-source-code)
5. [Downloading ESM Patches](#downloading-esm-patches)
6. [Applying ESM Modifications](#applying-esm-modifications)
7. [Building the ESM-Enabled AOSP](#building-the-esm-enabled-aosp)
8. [Flashing to Device](#flashing-to-device)
9. [Verification and Testing](#verification-and-testing)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Knowledge Requirements
- Basic Linux command line experience
- Understanding of Android architecture (helpful but not required)
- Familiarity with git and repo tools
- Patience (full build takes 2-4 hours on modern hardware)

### Legal Requirements
- Accept Android Open Source Project licenses
- Understand Google's terms for factory images and binaries
- Comply with export regulations for your region

---

## System Requirements

### Hardware Requirements

**Minimum**:
- CPU: 4-core x86_64 processor
- RAM: 16 GB
- Storage: 250 GB free space (SSD strongly recommended)
- Internet: Broadband connection for ~100 GB download

**Recommended**:
- CPU: 8-core or more (Ryzen 5/7, Intel i5/i7)
- RAM: 32 GB or more
- Storage: 400 GB free space on NVMe SSD
- Internet: High-speed connection (fiber/cable)

**Build Time Estimates**:
- 16-core CPU, 32GB RAM, NVMe SSD: ~45-60 minutes
- 8-core CPU, 16GB RAM, SATA SSD: ~90-120 minutes
- 4-core CPU, 16GB RAM, HDD: ~4-6 hours

### Software Requirements

**Operating System**:
- Ubuntu 18.04 LTS or newer (20.04/22.04 recommended)
- Other Linux distributions supported but not covered here
- macOS not recommended (compatibility issues)

**Required Packages**:
```bash
sudo apt-get update
sudo apt-get install -y \
    git-core gnupg flex bison build-essential zip curl zlib1g-dev \
    gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev \
    x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev \
    libxml2-utils xsltproc unzip fontconfig python3 python-is-python3 \
    bc cpio rsync libssl-dev
```

---

## Setting Up the Build Environment

### Step 1: Install Repo Tool

```bash
# Create bin directory for repo
mkdir -p ~/bin
export PATH=~/bin:$PATH

# Download repo tool
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo

# Add to PATH permanently
echo 'export PATH=~/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Verify installation
repo --version
```

### Step 2: Configure Git

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Step 3: Install Java (OpenJDK 11)

```bash
sudo apt-get install openjdk-11-jdk

# Verify installation
java -version
# Should show: openjdk version "11.x.x"
```

### Step 4: Increase File Descriptors Limit

```bash
# Temporary (current session)
ulimit -n 4096

# Permanent
echo "* soft nofile 4096" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 10240" | sudo tee -a /etc/security/limits.conf
```

### Step 5: Set Up ccache (Optional but Recommended)

```bash
# Install ccache
sudo apt-get install ccache

# Configure ccache for AOSP builds
export USE_CCACHE=1
export CCACHE_DIR=$HOME/.ccache
ccache -M 50G  # Adjust size based on available space

# Add to .bashrc
echo 'export USE_CCACHE=1' >> ~/.bashrc
echo 'export CCACHE_DIR=$HOME/.ccache' >> ~/.bashrc
```

---

## Downloading AOSP Source Code

### Step 1: Create Working Directory

```bash
mkdir -p ~/android/aosp_pixel5_esm
cd ~/android/aosp_pixel5_esm
```

### Step 2: Initialize Repo for Android 12

```bash
# Initialize repo for Android 12 (android-12.0.0_r3)
repo init -u https://android.googlesource.com/platform/manifest -b android-12.0.0_r3

# This will take a few minutes to initialize
```

**Branch Information**:
- Tag: `android-12.0.0_r3`
- Build ID: `SP1A.210812.016.A1`
- Released: September 2021
- Compatible with: Pixel 5 (redfin)

### Step 3: Download Source Code

```bash
# Start sync (this downloads ~80-100 GB)
repo sync -c -j8 --force-sync --no-clone-bundle --no-tags

# Options explained:
#   -c: Current branch only (saves space)
#   -j8: Use 8 parallel jobs (adjust based on your CPU)
#   --force-sync: Overwrite local changes
#   --no-clone-bundle: Don't use clone bundles (sometimes faster)
#   --no-tags: Don't fetch tags (saves bandwidth)

# This will take 2-6 hours depending on your connection
```

**If download fails**:
```bash
# Resume with same command
repo sync -c -j8 --force-sync --no-clone-bundle --no-tags
```

### Step 4: Download Device-Specific Binaries

Google Pixel devices require proprietary binaries for full functionality.

```bash
cd ~/android/aosp_pixel5_esm

# Download driver binaries for redfin (Pixel 5)
# Visit: https://developers.google.com/android/drivers
# Download for Build ID: SP1A.210812.016.A1

# Or use wget:
wget https://dl.google.com/dl/android/aosp/google_devices-redfin-sp1a.210812.016.a1-fe9bc5fb.tgz
wget https://dl.google.com/dl/android/aosp/qcom-redfin-sp1a.210812.016.a1-28a4cf6d.tgz

# Extract binaries
tar -xzf google_devices-redfin-sp1a.210812.016.a1-fe9bc5fb.tgz
tar -xzf qcom-redfin-sp1a.210812.016.a1-28a4cf6d.tgz

# Run extraction scripts
./extract-google_devices-redfin.sh
./extract-qcom-redfin.sh
```

**Accept licenses when prompted** - Read and type "I ACCEPT" for each.

---

## Downloading ESM Patches

### Option A: From Git Repository (If Available)

```bash
# If ESM patches are hosted in a git repository
cd ~/android
git clone https://github.com/your-repo/esm-android12-patches.git
cd esm-android12-patches

# Verify patch files
ls -la patches/
```

### Option B: Manual Patch Creation

If you have access to a working ESM build, generate patches:

```bash
cd ~/android/aosp_pixel5_esm

# Generate patches for each modified repository
repo forall -c '
    if git diff --quiet android-12.0.0_r3; then
        echo "No changes in $(pwd)"
    else
        PROJECT=$(basename $(pwd))
        PATCH_DIR=~/esm_patches/$PROJECT
        mkdir -p $PATCH_DIR
        git format-patch android-12.0.0_r3 --output-directory $PATCH_DIR
        echo "Created patches in $PATCH_DIR"
    fi
'
```

### Option C: Extract from This Codebase

```bash
# From the working ESM build directory
cd ~/android/aosp_pixel5_esm

# Create patch directory
mkdir -p ~/esm_patches

# Generate unified diff for all changes
repo forall -c "pwd; git diff android-12.0.0_r3" > ~/esm_patches/esm_all_changes.diff
```

---

## Applying ESM Modifications

### Method 1: Applying Unified Diff

If you have a single unified diff file:

```bash
cd ~/android/aosp_pixel5_esm

# Download or copy the ESM diff file
# Example: esm_all_changes.diff

# Apply patches by repository
# This requires manual separation by repository
# See detailed instructions below
```

### Method 2: Manual Code Changes

Based on the ESM implementation, here are the required changes:

#### Kernel Changes

**1. Download Kernel Source**:
```bash
cd ~/android/aosp_pixel5_esm
git clone https://android.googlesource.com/kernel/redbull kernel_redbull_source
cd kernel_redbull_source
git checkout android-4.19-stable

# Or download specific tag
git checkout android12-4.19-stable
```

**2. Create `kernel/esm.c`**:

Copy the complete ESM kernel implementation (see ESM_TECHNICAL_WIKI.md for details).

Location: `kernel_redbull_source/kernel/esm.c`

Key functions to implement:
- `esm_register()`
- `esm_wait()`
- `esm_deliver_event()`
- `esm_ctl()`
- `is_in_esm_wait()`

**CRITICAL**: Fix VLA issue - use `kmalloc()` instead of stack arrays.

**3. Modify `include/linux/sched.h`**:
```bash
cd kernel_redbull_source

# Edit include/linux/sched.h
# Add after other TASK_* definitions:
```
```c
#define TASK_EV_WAIT    0x0800  /* waiting for event stream */
```

**4. Add Syscall Numbers**:

Edit `arch/arm/tools/syscall.tbl`:
```
# Add at end of file:
443  common  esm_register            sys_esm_register
444  common  esm_wait                sys_esm_wait
445  common  esm_ctl                 sys_esm_ctl
446  common  is_in_esm_wait          sys_is_in_esm_wait
```

**5. Integrate with evdev Driver**:

Edit `drivers/input/evdev.c`:

Find the `evdev_events()` function and add ESM delivery:
```c
// In evdev_events() after processing each event
if (event->type != EV_SYN || event->code != SYN_REPORT) {
    esm_deliver_event(client->evdev->handle.dev, event);
}
```

**6. Update Kernel Makefile**:

Edit `kernel/Makefile`:
```makefile
# Add to core kernel objects
obj-y += esm.o
```

#### Bionic Changes

**1. Add Syscall Definitions**:

Edit `bionic/libc/SYSCALLS.TXT`:
```
# Add at end:
int esm_register(int, unsigned long) arm,arm64
int esm_wait(struct esm_event*, size_t, int) arm,arm64
int esm_ctl(int, unsigned long) arm,arm64
int is_in_esm_wait(pid_t) arm,arm64
```

**2. Create ESM Header**:

Create `bionic/libc/include/sys/esm.h` with:
- Event structures
- Control commands
- Function prototypes
- Documentation

(See complete header in technical wiki)

#### Framework Changes

**1. frameworks/native - InputFlinger**:

Modify `services/inputflinger/EventHub.cpp`:
- Add ESM registration for input devices
- Replace epoll with esm_wait()
- Handle batched events

**2. frameworks/base - Watchdog**:

Modify `services/core/java/com/android/server/Watchdog.java`:
- Add JNI call to `is_in_esm_wait()`
- Skip ANR check for processes in ESM wait state

**3. libcore - Java Constants**:

Modify `luni/src/main/java/android/system/OsConstants.java`:
- Add ESM syscall number constants
- Add event type constants

### Automated Patch Application Script

```bash
#!/bin/bash
# apply_esm_patches.sh

set -e

AOSP_ROOT=~/android/aosp_pixel5_esm
ESM_PATCHES=~/esm_patches

echo "Applying ESM patches to AOSP..."

# Array of repositories to patch
declare -A REPOS
REPOS=(
    ["bionic"]="$AOSP_ROOT/bionic"
    ["frameworks/native"]="$AOSP_ROOT/frameworks/native"
    ["frameworks/base"]="$AOSP_ROOT/frameworks/base"
    ["libcore"]="$AOSP_ROOT/libcore"
    ["kernel"]="$AOSP_ROOT/kernel_redbull_source"
)

# Apply patches
for repo in "${!REPOS[@]}"; do
    REPO_PATH="${REPOS[$repo]}"
    PATCH_DIR="$ESM_PATCHES/$repo"

    if [ -d "$PATCH_DIR" ]; then
        echo "Applying patches for $repo..."
        cd "$REPO_PATH"
        git am "$PATCH_DIR"/*.patch
    else
        echo "No patches found for $repo"
    fi
done

echo "ESM patches applied successfully!"
```

### Verification After Patching

```bash
cd ~/android/aosp_pixel5_esm

# Check for modified files in each repo
repo forall -c "git status | grep -q modified && echo \$(pwd): \$(git status --short | wc -l) files modified"

# Expected output:
# ~/android/aosp_pixel5_esm/bionic: X files modified
# ~/android/aosp_pixel5_esm/frameworks/native: Y files modified
# ~/android/aosp_pixel5_esm/frameworks/base: Z files modified
# ~/android/aosp_pixel5_esm/libcore: W files modified
# ~/android/aosp_pixel5_esm/kernel_redbull_source: V files modified
```

---

## Building the ESM-Enabled AOSP

### Step 1: Set Up Build Environment

```bash
cd ~/android/aosp_pixel5_esm

# Source build environment
source build/envsetup.sh

# Select build target
lunch aosp_redfin-userdebug

# You should see:
# ============================================
# PLATFORM_VERSION_CODENAME=REL
# PLATFORM_VERSION=12
# TARGET_PRODUCT=aosp_redfin
# TARGET_BUILD_VARIANT=userdebug
# ...
# ============================================
```

**Build Variant Options**:
- `userdebug`: Recommended for development (has root access, debugging tools)
- `user`: Production-like build (no root, optimized)
- `eng`: Engineering build (all debugging enabled)

### Step 2: Build ESM Kernel

The kernel must be built separately before the main AOSP build.

**Option A: Using Provided Build Script**:
```bash
cd ~/android/aosp_pixel5_esm

# Copy build scripts
# (These should be included with ESM patches)
cp esm_patches/build_esm_kernel.sh device/google/redfin/
chmod +x device/google/redfin/build_esm_kernel.sh

# Build kernel
bash device/google/redfin/build_esm_kernel.sh
```

**Option B: Manual Kernel Build**:
```bash
cd ~/android/aosp_pixel5_esm

# Set up paths
export AOSP_ROOT=$(pwd)
export KERNEL_SRC=$AOSP_ROOT/kernel_redbull_source
export KERNEL_OUT=$AOSP_ROOT/out/target/product/redfin/obj/KERNEL_OBJ
export CLANG_PATH=$AOSP_ROOT/prebuilts/clang/host/linux-x86/clang-r416183b
export PATH=$CLANG_PATH/bin:$PATH

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

# Build kernel
make -C $KERNEL_SRC O=$KERNEL_OUT \
    ARCH=arm64 \
    LLVM=1 \
    LLVM_IAS=1 \
    CLANG_TRIPLE=aarch64-linux-gnu- \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
    -j$(nproc) \
    Image.lz4-dtb

# Kernel image will be at:
# $KERNEL_OUT/arch/arm64/boot/Image.lz4-dtb
```

**Expected Build Time**: 3-7 minutes on modern hardware

### Step 3: Build AOSP with ESM

**Option A: Using All-in-One Build Script**:

If you have the wrapper script (recommended):
```bash
cd ~/android/aosp_pixel5_esm

# Build everything (kernel + Android)
./build.sh -j$(nproc)

# Or with specific job count
./build.sh -j32
```

**Option B: Manual AOSP Build**:
```bash
cd ~/android/aosp_pixel5_esm

# Ensure environment is set up
source build/envsetup.sh
lunch aosp_redfin-userdebug

# Start build
time m -j$(nproc)

# Monitor progress
# You'll see: [  1% 234/26960] compiling ...
```

**Build Time Estimates**:
- First build (clean): 1-4 hours depending on hardware
- Incremental builds: 2-15 minutes

**Build Progress Indicators**:
```
[  0% 1/26960]    - Just starting
[ 25% 6740/26960] - Kernel and core libraries
[ 50% 13480/26960]- Framework and services
[ 75% 20220/26960]- Applications and resources
[100% 26960/26960]- Final packaging
```

### Step 4: Monitor Build

**In another terminal**:
```bash
# Watch build progress
watch -n 5 'grep building out/.module_paths/Android.bp.list | tail -20'

# Check system resources
htop

# Monitor ccache hit rate
ccache -s
```

**Common Build Warnings** (usually safe to ignore):
- `warning: LOCAL_COPY_HEADERS is deprecated`
- `warning: BOARD_PLAT_PUBLIC_SEPOLICY_DIR has been deprecated`

### Step 5: Build Completion

When build completes successfully:
```
#### build completed successfully (01:23:45 (hh:mm:ss)) ####
```

Build artifacts location:
```
out/target/product/redfin/
├── boot.img          # Boot image (kernel + ramdisk)
├── system.img        # System partition
├── vendor.img        # Vendor partition
├── product.img       # Product partition
├── system_ext.img    # System extensions
├── userdata.img      # User data partition
└── ...
```

---

## Flashing to Device

### Prerequisites

1. **Unlock Bootloader**:
   ```bash
   # Enable Developer Options on device:
   # Settings → About Phone → Tap "Build Number" 7 times

   # Enable OEM Unlocking:
   # Settings → System → Developer Options → Enable "OEM unlocking"

   # Reboot to bootloader
   adb reboot bootloader

   # Unlock (THIS WILL WIPE YOUR DEVICE)
   fastboot flashing unlock

   # Confirm on device screen
   ```

2. **Backup Data** (bootloader unlock wipes device)

### Method 1: Flash All Images (Recommended for First Flash)

```bash
cd ~/android/aosp_pixel5_esm/out/target/product/redfin

# Reboot to bootloader
adb reboot bootloader

# Wait for bootloader mode (screen shows Android with "Start")

# Flash all partitions
fastboot flashall -w

# Options:
#   -w: Wipe userdata (factory reset)

# Wait for flash to complete (2-3 minutes)
```

### Method 2: Flash Individual Images

```bash
cd ~/android/aosp_pixel5_esm/out/target/product/redfin

adb reboot bootloader

# Flash bootloader (if updated)
fastboot flash bootloader bootloader.img

# Flash radio (if updated)
fastboot flash radio radio.img

# Reboot bootloader
fastboot reboot-bootloader

# Flash system partitions
fastboot flash boot boot.img
fastboot flash system system.img
fastboot flash vendor vendor.img
fastboot flash product product.img
fastboot flash system_ext system_ext.img

# Optionally wipe userdata (factory reset)
fastboot -w

# Reboot
fastboot reboot
```

### Method 3: Flash Over ADB (For Development)

```bash
cd ~/android/aosp_pixel5_esm

# Device must be rooted with adbd running as root
adb root
adb remount

# Sync system files
adb sync system

# Reboot
adb reboot
```

### First Boot

- **Expected boot time**: 2-5 minutes (first boot is slow)
- Device will show Google logo, then Android setup
- Complete Android setup wizard
- ESM is now active in the kernel

---

## Verification and Testing

### 1. Verify ESM Kernel

```bash
# Connect device
adb shell

# Check kernel version
uname -r
# Should show: 4.19.x-... with your build date

# Verify ESM syscalls exist
cat /proc/kallsyms | grep esm
# Should show: esm_register, esm_wait, esm_ctl, is_in_esm_wait

# Check kernel log for ESM initialization
dmesg | grep -i esm
# Should show ESM-related messages
```

### 2. Test ESM Functionality

```bash
# Create test program on device
adb shell

cat > /data/local/tmp/esm_test.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <sys/esm.h>
#include <linux/input.h>

int main() {
    int fd = open("/dev/input/event0", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (esm_register(fd, (1 << EV_KEY) | (1 << EV_ABS)) < 0) {
        perror("esm_register");
        return 1;
    }

    printf("ESM registered successfully!\n");
    printf("Waiting for events (touch the screen)...\n");

    struct esm_event events[10];
    int n = esm_wait(events, 10, 5000); // 5 second timeout

    if (n < 0) {
        perror("esm_wait");
    } else {
        printf("Received %d events\n", n);
        for (int i = 0; i < n; i++) {
            printf("Event: fd=%d type=%d code=%d value=%d\n",
                   events[i].fd,
                   events[i].event.type,
                   events[i].event.code,
                   events[i].event.value);
        }
    }

    close(fd);
    return 0;
}
EOF

# Compile test program
# (Requires NDK or on-device compiler - simplified test only)
```

### 3. Check InputFlinger Integration

```bash
adb shell

# Check if InputFlinger is running
ps -A | grep inputflinger

# Monitor InputFlinger logs
logcat -s InputReader:V InputDispatcher:V | grep -i esm
```

### 4. Performance Testing

```bash
# Measure touch latency
adb shell getevent -lt /dev/input/event0
# Tap screen, observe timestamp differences

# Check CPU usage
adb shell top | grep system_server

# Monitor wakeups
adb shell cat /proc/wakelocks
```

### 5. Regression Testing

Ensure existing functionality still works:
- [ ] Touch screen responsive
- [ ] Keyboard input works
- [ ] Gestures functional
- [ ] Apps launch normally
- [ ] Camera works
- [ ] Phone calls
- [ ] Wi-Fi/Bluetooth
- [ ] GPS

---

## Troubleshooting

### Build Errors

**Error: `make: *** No rule to make target`**
```bash
# Clean and rebuild
make clobber
source build/envsetup.sh
lunch aosp_redfin-userdebug
m -j$(nproc)
```

**Error: `FAILED: out/target/product/redfin/kernel`**
```bash
# Kernel build failed - check kernel separately
cd kernel_redbull_source
make clean
# Then rebuild kernel manually (see Step 2 above)
```

**Error: VLA compilation error in kernel/esm.c**
```bash
# Check that VLA fix is applied correctly
grep -A 10 "struct esm_event \*batch" kernel_redbull_source/kernel/esm.c
# Should show kmalloc() allocation, not array declaration
```

**Error: `Out of memory`**
```bash
# Reduce parallel jobs
m -j4  # Instead of -j$(nproc)

# Add swap space
sudo fallocate -l 16G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Flash Errors

**Error: `FAILED (remote: 'Partition not found')`**
```bash
# Update bootloader and radio first
fastboot flash bootloader bootloader.img
fastboot flash radio radio.img
fastboot reboot-bootloader
# Then flash system images
```

**Error: Device stuck at Google logo**
```bash
# Boot to recovery and factory reset
# Hold Power + Volume Down → Select Recovery
# Then: Factory Reset

# Or via fastboot
fastboot -w
fastboot reboot
```

**Error: Bootloop**
```bash
# Flash stock factory image to recover
# Download from: https://developers.google.com/android/images
# Extract and run flash-all.sh
```

### Runtime Errors

**ESM syscalls return -ENOSYS**
```bash
# Kernel doesn't have ESM support
# Verify kernel build includes ESM:
adb shell "cat /proc/kallsyms | grep esm"

# If empty, kernel needs to be rebuilt with ESM
```

**InputFlinger crashes**
```bash
# Check logs
adb logcat -b crash

# Check for ESM-related crashes
adb logcat | grep -i "esm\|inputflinger"

# May need to disable ESM in InputFlinger and rebuild
```

**High battery drain**
```bash
# Check ESM statistics
adb shell "echo 'ESM stats check here'"

# Monitor wakeups
adb shell dumpsys batterystats | grep -i wakeup
```

---

## Appendix

### A. Quick Reference Commands

```bash
# Download AOSP
repo init -u https://android.googlesource.com/platform/manifest -b android-12.0.0_r3
repo sync -c -j8 --no-tags

# Build everything
source build/envsetup.sh
lunch aosp_redfin-userdebug
./build.sh -j32

# Flash device
adb reboot bootloader
fastboot flashall -w

# Verify
adb shell cat /proc/kallsyms | grep esm
```

### B. Directory Structure

```
~/android/aosp_pixel5_esm/
├── bionic/                 # C library (libc)
├── frameworks/
│   ├── base/              # Framework services
│   └── native/            # Native services
├── libcore/               # Java core libraries
├── kernel_redbull_source/ # Kernel source (manually cloned)
├── device/
│   └── google/
│       └── redfin/        # Pixel 5 device config
├── out/                   # Build output
│   └── target/
│       └── product/
│           └── redfin/    # Build artifacts
└── build/
    └── make/              # Build system
        └── build_esm.sh   # ESM build script
```

### C. File Sizes Reference

```
Full AOSP source:        ~80 GB
Build output:            ~100 GB
Kernel source:          ~2 GB
Total space needed:     ~200-250 GB

Built images:
- boot.img:             ~64 MB
- system.img:          ~2.5 GB
- vendor.img:          ~800 MB
- userdata.img:        ~100 MB (empty)
```

### D. Useful Links

- AOSP Source: https://source.android.com
- Device Binaries: https://developers.google.com/android/drivers
- Factory Images: https://developers.google.com/android/images
- Pixel 5 Info: https://source.android.com/docs/setup/about/build-numbers#source-code-tags-and-builds
- Build Help: https://source.android.com/docs/setup/build/building
- Flashing Guide: https://source.android.com/docs/setup/build/running

### E. Common Variables

```bash
# AOSP Build Variables
export ANDROID_BUILD_TOP=~/android/aosp_pixel5_esm
export OUT_DIR=out
export DIST_DIR=dist
export USE_CCACHE=1
export CCACHE_DIR=$HOME/.ccache

# Kernel Build Variables
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
export LLVM=1
export LLVM_IAS=1
```

---

## Support and Contributing

### Getting Help

1. Check this guide and ESM_TECHNICAL_WIKI.md
2. Search AOSP documentation
3. Check kernel build logs
4. Review logcat output

### Known Issues

1. **VLA Compilation Error**: Fixed in provided patches (use kmalloc)
2. **Blueprint File Scanning**: Disabled (*.bp.disabled)
3. **PATH Restrictions**: Build script works around Android build system limitations

### Document Version

- **Version**: 1.0
- **Date**: 2025-11-11
- **Android Version**: 12 (android-12.0.0_r3)
- **Build ID**: SP1A.210812.016.A1
- **Device**: Google Pixel 5 (redfin)
- **Kernel**: 4.19 (redbull)

---

**Remember**: Building AOSP is a complex process. Don't be discouraged by errors. Most issues have solutions, and the process becomes easier with practice.

**Good luck with your build!**
