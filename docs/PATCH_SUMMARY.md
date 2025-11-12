# ESM Patch Summary

This document provides a concise overview of all changes required to integrate ESM into Android 12.

## Patches Overview

| Repository | Patch File | Lines Changed | Description |
|------------|------------|---------------|-------------|
| kernel_redbull_source | kernel_redbull.patch | 1071 | Core ESM implementation + evdev integration |
| bionic | bionic.patch | 186 | ESM syscall definitions and headers |
| frameworks/native | frameworks_native.patch | 327 | InputFlinger ESM integration |
| frameworks/base | frameworks_base.patch | 153 | Watchdog ESM awareness |
| libcore | libcore.patch | 113 | Java constants for ESM |
| build/make | build_make.patch | 144 | Build system integration |
| device/google/redfin | device_google_redfin.patch | 155 | Pixel 5 device configuration |

**Total**: 7 repositories, 2,149 lines changed

---

## Detailed Changes by Component

### 1. Kernel (kernel_redbull.patch)

#### New Files
- **kernel/esm.c** (~1000 lines)
  - `esm_register()` - Register file descriptor for event delivery
  - `esm_wait()` - Wait for events with timeout
  - `esm_push_event()` - Push event from driver to registered processes
  - `esm_ctl()` - Control ESM behavior
  - `is_in_esm_wait()` - Check if process is in ESM wait state

#### Modified Files
- **drivers/input/evdev.c**
  - `evdev_events()` - Call `esm_push_event()` for each input event
  - **Critical fix**: Push once per device using `list_first_or_null_rcu()`, not once per client

- **include/linux/sched.h**
  - Add `TASK_EV_WAIT` state (0x0800)

- **arch/arm64/include/uapi/asm/unistd.h**
  - Add syscall numbers: 443-446

- **arch/arm64/include/asm/unistd32.h**
  - Add 32-bit syscall mappings

- **include/uapi/asm-generic/unistd.h**
  - Declare ESM syscalls

- **kernel/Makefile**
  - Add `esm.o` to kernel objects

#### Key Implementation Details
- Uses **kmalloc()** instead of VLA (critical for kernel compatibility)
- **Inode-based matching** for event delivery (not fd-based)
- **Per-device kfifo queues** (128 events each)
- **Global spinlock** for context list (future: per-context locks)
- **RCU-protected** client list iteration in evdev

---

### 2. Bionic (bionic.patch)

#### New Files
- **bionic/libc/include/sys/esm.h**
  ```c
  struct esm_event {
      int fd;
      struct input_event event;
  };

  int esm_register(int fd, unsigned long event_mask);
  int esm_wait(struct esm_event *events, size_t max_events, int timeout_ms);
  int esm_ctl(int cmd, unsigned long arg);
  int is_in_esm_wait(pid_t pid);
  ```

#### Modified Files
- **bionic/libc/SYSCALLS.TXT**
  ```
  int esm_register(int, unsigned long) arm,arm64
  int esm_wait(struct esm_event*, size_t, int) arm,arm64
  int esm_ctl(int, unsigned long) arm,arm64
  int is_in_esm_wait(pid_t) arm,arm64
  ```

- **bionic/libc/include/linux/input.h** (if needed)
  - Ensure `struct input_event` is defined

---

### 3. Frameworks/Native (frameworks_native.patch)

#### Modified Files
- **services/inputflinger/reader/EventHub.cpp**

**Key Changes**:
1. Include ESM header: `#include <sys/esm.h>`

2. Register devices with ESM:
   ```cpp
   if (esm_register(fd, (1 << EV_KEY) | (1 << EV_ABS) | (1 << EV_REL) | (1 << EV_SW)) < 0) {
       ALOGE("ESM: Failed to register device fd=%d: %s", fd, strerror(errno));
       // Fallback to epoll
   }
   ```

3. Replace `epoll_wait()` with `esm_wait()`:
   ```cpp
   struct esm_event esm_events[64];
   int event_count = esm_wait(esm_events, 64, timeoutMillis);

   if (event_count < 0) {
       if (errno == ENOSYS) {
           // ESM not supported, fallback to epoll
       }
   }

   for (int i = 0; i < event_count; i++) {
       // Process esm_events[i].event directly
       // esm_events[i].fd identifies which device
   }
   ```

4. Handle batched events:
   - Events from multiple devices arrive in single call
   - No need for separate read() calls
   - SYN_REPORT boundaries already handled by kernel

5. Add ESM debug logging:
   ```cpp
   ALOGI("ESM: Received %d events", event_count);
   ```

**Lines Changed**: ~150 lines (add ESM path, keep epoll as fallback)

---

### 4. Frameworks/Base (frameworks_base.patch)

#### Modified Files
- **services/core/java/com/android/server/Watchdog.java**

**Key Changes**:
1. Add native method declaration:
   ```java
   private static native boolean isInEsmWait(int pid);
   ```

2. Modify ANR check:
   ```java
   if (!isInEsmWait(systemServerPid)) {
       // Process is not legitimately waiting on ESM
       // Check for ANR
   }
   ```

3. Add JNI implementation (C++ side):
   ```cpp
   #include <sys/esm.h>

   jboolean isInEsmWait(JNIEnv* env, jclass clazz, jint pid) {
       return is_in_esm_wait((pid_t)pid) ? JNI_TRUE : JNI_FALSE;
   }
   ```

**Why**: Prevents false ANR (Application Not Responding) reports when InputFlinger is legitimately blocked in `esm_wait()` waiting for user input.

---

### 5. Libcore (libcore.patch)

#### Modified Files
- **luni/src/main/java/android/system/OsConstants.java**

**Key Changes**:
```java
// ESM syscall numbers
public static final int SYS_esm_register = 443;
public static final int SYS_esm_wait = 444;
public static final int SYS_esm_ctl = 445;
public static final int SYS_is_in_esm_wait = 446;

// Event types (for event_mask)
public static final int EV_SYN = 0x00;
public static final int EV_KEY = 0x01;
public static final int EV_REL = 0x02;
public static final int EV_ABS = 0x03;
```

**Why**: Allows Java code to reference ESM constants.

---

### 6. Build/Make (build_make.patch)

#### Modified Files
- **core/Makefile** or **core/main.mk**

**Key Changes**:
1. Add kernel build step:
   ```make
   .PHONY: build_kernel
   build_kernel:
   	@echo "Building ESM kernel..."
   	$(MAKE) -C kernel_redbull_source O=$(KERNEL_OUT) \
   		ARCH=arm64 LLVM=1 Image.lz4-dtb

   $(INSTALLED_KERNEL_TARGET): build_kernel
   	cp $(KERNEL_OUT)/arch/arm64/boot/Image.lz4-dtb $@
   ```

2. Add dependency:
   ```make
   $(INSTALLED_BOOTIMAGE_TARGET): $(INSTALLED_KERNEL_TARGET)
   ```

**Why**: Ensures ESM kernel is built automatically during AOSP build.

---

### 7. Device Config (device_google_redfin.patch)

#### Modified Files
- **device/google/redfin/device.mk**

**Key Changes**:
```make
# Enable ESM kernel
BOARD_KERNEL_IMAGE_NAME := Image.lz4-dtb
TARGET_KERNEL_SOURCE := kernel_redbull_source
TARGET_KERNEL_CONFIG := redbull_defconfig

# ESM compile flags
BOARD_KERNEL_CMDLINE += esm.enabled=1
```

- **device/google/redfin/BoardConfig.mk**
```make
# Kernel build configuration
BOARD_KERNEL_BASE := 0x00000000
BOARD_KERNEL_PAGESIZE := 4096
TARGET_PREBUILT_KERNEL := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/arch/arm64/boot/Image.lz4-dtb
```

**Why**: Configures Pixel 5-specific kernel build parameters.

---

## Critical Fixes Included

### 1. VLA Elimination (kernel)

**Problem**: Original code used Variable Length Array on kernel stack:
```c
struct esm_event batch[max_events];  // WRONG - causes kernel panic
```

**Fix**: Use dynamic allocation:
```c
struct esm_event *batch = kmalloc(max_events * sizeof(struct esm_event), GFP_KERNEL);
// ... use batch ...
kfree(batch);
```

### 2. Duplicate Event Fix (evdev)

**Problem**: Events pushed once per evdev client, causing duplicates:
```c
list_for_each_entry_rcu(client, &evdev->client_list, node) {
    esm_push_event(client->file, &event);  // WRONG - called N times
}
```

**Fix**: Push once using first client's file:
```c
client = list_first_or_null_rcu(&evdev->client_list, struct evdev_client, node);
if (client && client->file)
    esm_push_event(client->file, &event);  // RIGHT - called once
```

**Impact**: Fixed power button opening camera on single press.

---

## Syscall Interface

### esm_register
```c
int esm_register(int fd, unsigned long event_mask);
```
- **fd**: File descriptor to `/dev/input/eventX`
- **event_mask**: Bitmask of event types (1 << EV_KEY | 1 << EV_ABS, etc.)
- **Returns**: 0 on success, -1 on error (errno set)

### esm_wait
```c
int esm_wait(struct esm_event *events, size_t max_events, int timeout_ms);
```
- **events**: Buffer to receive events
- **max_events**: Maximum events to return
- **timeout_ms**: Timeout in milliseconds (-1 = infinite)
- **Returns**: Number of events received, 0 on timeout, -1 on error

### esm_ctl
```c
int esm_ctl(int cmd, unsigned long arg);
```
- **cmd**: Control command (future use)
- **arg**: Command argument
- **Returns**: 0 on success, -1 on error

### is_in_esm_wait
```c
int is_in_esm_wait(pid_t pid);
```
- **pid**: Process ID to check
- **Returns**: 1 if in ESM wait, 0 otherwise

---

## Build Order

When building AOSP with ESM, components must be built in this order:

1. **Kernel** (kernel_redbull_source)
   - Must be built first as it provides ESM syscalls

2. **Bionic** (bionic)
   - Depends on kernel syscall numbers

3. **Frameworks** (frameworks/native, frameworks/base)
   - Depends on bionic headers

4. **Applications** (everything else)
   - Depends on frameworks

The automated build scripts handle this correctly.

---

## Testing Checklist

After applying patches and building:

- [ ] Kernel has ESM symbols: `cat /proc/kallsyms | grep esm`
- [ ] InputFlinger uses ESM: `logcat | grep -i esm`
- [ ] Touch screen works
- [ ] Keyboard input works
- [ ] Buttons work (power, volume)
- [ ] Power button doesn't open camera on single press
- [ ] No ANR false positives
- [ ] Lower latency (use `getevent -lt` to measure)

---

## Performance Targets

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Latency reduction | 20-30% | `getevent -lt` timestamps |
| CPU reduction | 10-15% | `top` during interaction |
| Syscall reduction | >90% | `strace -c` on InputFlinger |
| Battery improvement | 5-10% | 30 min usage test |

---

## References

- **Full Technical Docs**: See `ESM_TECHNICAL.md`
- **Build Guide**: See `QUICKSTART.md` or `ESM_BUILD_HOWTO.md`
- **Main README**: See `../README.md`

---

**Document Version**: 1.0
**Date**: 2025-11-12
**Maintained**: Yes
