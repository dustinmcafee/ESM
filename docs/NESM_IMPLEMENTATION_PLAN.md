# Network Event Stream Model (NESM) Implementation Plan

## Project Overview

Extend the Event Stream Model to network stack for power-efficient packet delivery in Android 12.

**Goal**: Reduce syscall overhead and power consumption for network I/O by 30-50%

**Timeline**: 8-12 weeks for production-ready implementation

**Target Device**: Google Pixel 5 (Android 12)

---

## Phase 1: Kernel NESM Core (2-3 weeks)

### 1.1 Create NESM Driver Skeleton

**Files to Create**:
- `kernel_redbull_source/kernel/nesm.c` (~1500 lines)
- `kernel_redbull_source/include/linux/nesm.h` (~200 lines)
- `kernel_redbull_source/include/uapi/linux/nesm.h` (~150 lines)

**Core Data Structures**:

```c
// include/linux/nesm.h

struct nesm_context {
    struct task_struct *task;
    struct hlist_node list;
    struct hlist_head sockets[256];  // Hash table of registered sockets
    wait_queue_head_t wait_queue;
    spinlock_t lock;
    u64 packets_received;
    atomic_t batch_ready;
};

struct nesm_socket {
    struct socket *sock;
    struct inode *inode;
    unsigned long protocol_mask;  // (1 << IPPROTO_UDP) | (1 << IPPROTO_TCP)

    // Queue for sk_buff pointers
    DECLARE_KFIFO(skb_queue, struct sk_buff *, 256);

    spinlock_t lock;
    atomic_t queue_size_bytes;  // Flow control
    struct hlist_node hash_node;
};

struct nesm_event {
    int fd;
    int protocol;
    size_t len;
    unsigned char data[2048];  // Or larger, configurable
};
```

**Core Functions**:

```c
// Syscall implementations
SYSCALL_DEFINE2(nesm_register, int, sockfd, unsigned long, proto_mask);
SYSCALL_DEFINE3(nesm_wait, struct nesm_event __user *, events,
                size_t, max_events, int, timeout_ms);
SYSCALL_DEFINE2(nesm_ctl, int, cmd, unsigned long, arg);
SYSCALL_DEFINE1(nesm_unregister, int, sockfd);

// Internal API
int nesm_push_packet(struct socket *sock, struct sk_buff *skb);
struct nesm_context *nesm_context_alloc(struct task_struct *task);
void nesm_context_free(struct nesm_context *ctx);
```

**Deliverables**:
- [ ] Basic nesm.c with context management
- [ ] Syscall stubs (return -ENOSYS for now)
- [ ] Kernel compiles successfully
- [ ] Module can be loaded

**Success Criteria**:
- `dmesg | grep nesm` shows initialization messages
- `cat /proc/kallsyms | grep nesm` shows symbols

---

### 1.2 Implement nesm_register()

**Implementation**:

```c
SYSCALL_DEFINE2(nesm_register, int, sockfd, unsigned long, proto_mask)
{
    struct fd f;
    struct socket *sock;
    struct nesm_context *ctx;
    struct nesm_socket *nsock;

    // Get socket from fd
    f = fdget(sockfd);
    if (!f.file)
        return -EBADF;

    sock = sock_from_file(f.file);
    if (!sock) {
        fdput(f);
        return -ENOTSOCK;
    }

    // Get or create ESM context for current task
    ctx = current->nesm_context;
    if (!ctx) {
        ctx = nesm_context_alloc(current);
        if (!ctx) {
            fdput(f);
            return -ENOMEM;
        }
        current->nesm_context = ctx;
    }

    // Create nesm_socket entry
    nsock = kmalloc(sizeof(*nsock), GFP_KERNEL);
    if (!nsock) {
        fdput(f);
        return -ENOMEM;
    }

    nsock->sock = sock;
    nsock->inode = f.file->f_inode;
    nsock->protocol_mask = proto_mask;
    INIT_KFIFO(nsock->skb_queue);
    spin_lock_init(&nsock->lock);
    atomic_set(&nsock->queue_size_bytes, 0);

    // Add to context's hash table
    spin_lock(&ctx->lock);
    hash_add(ctx->sockets, &nsock->hash_node, (unsigned long)nsock->inode);
    spin_unlock(&ctx->lock);

    fdput(f);

    pr_info("NESM: Registered socket fd=%d inode=%p proto_mask=0x%lx\n",
            sockfd, nsock->inode, proto_mask);

    return 0;
}
```

**Testing**:
```c
// Simple test module
int fd = socket(AF_INET, SOCK_DGRAM, 0);
int ret = syscall(__NR_nesm_register, fd, (1 << IPPROTO_UDP));
printk("nesm_register returned: %d\n", ret);
```

**Deliverables**:
- [ ] nesm_register() fully implemented
- [ ] Context allocation/deallocation working
- [ ] Hash table management correct
- [ ] Test module confirms registration works

---

### 1.3 Implement nesm_wait()

**Implementation**:

```c
SYSCALL_DEFINE3(nesm_wait, struct nesm_event __user *, events,
                size_t, max_events, int, timeout_ms)
{
    struct nesm_context *ctx = current->nesm_context;
    struct nesm_event *batch;
    struct nesm_socket *nsock;
    int count = 0;
    int bkt;

    if (!ctx)
        return -EINVAL;

    if (!max_events || max_events > 1024)
        return -EINVAL;

    // Allocate kernel buffer
    batch = kmalloc(max_events * sizeof(struct nesm_event), GFP_KERNEL);
    if (!batch)
        return -ENOMEM;

    // Wait for events (or timeout)
    if (timeout_ms >= 0) {
        wait_event_interruptible_timeout(ctx->wait_queue,
                                         nesm_has_events(ctx),
                                         msecs_to_jiffies(timeout_ms));
    } else {
        wait_event_interruptible(ctx->wait_queue,
                                 nesm_has_events(ctx));
    }

    // Collect events from all registered sockets
    spin_lock(&ctx->lock);
    hash_for_each(ctx->sockets, bkt, nsock, hash_node) {
        struct sk_buff *skb;

        spin_lock(&nsock->lock);
        while (count < max_events && kfifo_out(&nsock->skb_queue, &skb, 1)) {
            // Copy packet data to batch
            batch[count].fd = nsock->sock->file->fd;
            batch[count].protocol = skb->sk->sk_protocol;
            batch[count].len = min_t(size_t, skb->len, sizeof(batch[count].data));

            skb_copy_bits(skb, 0, batch[count].data, batch[count].len);

            // Update stats and free skb
            atomic_sub(skb->len, &nsock->queue_size_bytes);
            kfree_skb(skb);

            count++;
        }
        spin_unlock(&nsock->lock);
    }
    spin_unlock(&ctx->lock);

    // Copy to userspace
    if (copy_to_user(events, batch, count * sizeof(struct nesm_event))) {
        kfree(batch);
        return -EFAULT;
    }

    kfree(batch);
    ctx->packets_received += count;

    return count;
}

static bool nesm_has_events(struct nesm_context *ctx)
{
    struct nesm_socket *nsock;
    int bkt;

    hash_for_each(ctx->sockets, bkt, nsock, hash_node) {
        if (!kfifo_is_empty(&nsock->skb_queue))
            return true;
    }
    return false;
}
```

**Deliverables**:
- [ ] nesm_wait() implemented with proper blocking
- [ ] Timeout handling works correctly
- [ ] Event batching from multiple sockets
- [ ] Memory management (kmalloc/kfree) correct

---

### 1.4 Integrate with UDP Stack

**Hook Point**: `net/ipv4/udp.c` in `udp_queue_rcv_skb()`

```c
// net/ipv4/udp.c

int udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    // ... existing UDP processing ...

    // NESM: Push to event stream if registered
    if (sk->sk_socket && sk->sk_socket->file) {
        nesm_push_packet(sk->sk_socket, skb);
    }

    // Continue with normal socket buffer queuing
    return __udp_queue_rcv_skb(sk, skb);
}
```

**nesm_push_packet() Implementation**:

```c
int nesm_push_packet(struct socket *sock, struct sk_buff *skb)
{
    struct nesm_context *ctx;
    struct inode *inode = sock->file->f_inode;
    unsigned long flags;
    int delivered = 0;

    // Iterate all NESM contexts (similar to input ESM)
    spin_lock_irqsave(&nesm_global_lock, flags);
    list_for_each_entry(ctx, &nesm_context_list, list) {
        struct nesm_socket *nsock;
        int bkt;

        spin_lock(&ctx->lock);
        hash_for_each(ctx->sockets, bkt, nsock, hash_node) {
            if (nsock->inode == inode) {
                // Check protocol mask
                if (nsock->protocol_mask & (1 << skb->sk->sk_protocol)) {
                    // Check queue size for flow control
                    if (atomic_read(&nsock->queue_size_bytes) < MAX_QUEUE_BYTES) {
                        spin_lock(&nsock->lock);

                        // Clone skb (original still needs to go to socket buffer)
                        struct sk_buff *skb_copy = skb_clone(skb, GFP_ATOMIC);
                        if (skb_copy && kfifo_in(&nsock->skb_queue, &skb_copy, 1)) {
                            atomic_add(skb->len, &nsock->queue_size_bytes);
                            delivered = 1;
                        }

                        spin_unlock(&nsock->lock);
                    }
                }
                break;
            }
        }
        spin_unlock(&ctx->lock);

        // Wake waiting task
        if (delivered)
            wake_up(&ctx->wait_queue);
    }
    spin_unlock_irqrestore(&nesm_global_lock, flags);

    return delivered;
}
```

**Deliverables**:
- [ ] UDP hook integrated
- [ ] Packets delivered to NESM queues
- [ ] Flow control prevents queue overflow
- [ ] No packet loss in normal conditions

**Testing**:
```bash
# Send UDP packets to test socket
echo "test packet" | nc -u localhost 12345

# Check kernel logs
dmesg | grep "NESM: pushed packet"
```

---

### 1.5 Add Syscall Numbers

**File**: `arch/arm/tools/syscall.tbl`

```
447  common  nesm_register       sys_nesm_register
448  common  nesm_wait           sys_nesm_wait
449  common  nesm_ctl            sys_nesm_ctl
450  common  nesm_unregister     sys_nesm_unregister
```

**File**: `kernel_redbull_source/include/linux/syscalls.h`

```c
asmlinkage long sys_nesm_register(int sockfd, unsigned long proto_mask);
asmlinkage long sys_nesm_wait(struct nesm_event __user *events,
                               size_t max_events, int timeout_ms);
asmlinkage long sys_nesm_ctl(int cmd, unsigned long arg);
asmlinkage long sys_nesm_unregister(int sockfd);
```

**Deliverables**:
- [ ] Syscalls registered in syscall table
- [ ] Kernel compiles with new syscalls
- [ ] Syscalls accessible from userspace

---

## Phase 2: Bionic Integration (1 week)

### 2.1 Add Syscall Wrappers

**File**: `bionic/libc/SYSCALLS.TXT`

```
int nesm_register(int, unsigned long) arm,arm64
int nesm_wait(struct nesm_event*, size_t, int) arm,arm64
int nesm_ctl(int, unsigned long) arm,arm64
int nesm_unregister(int) arm,arm64
```

**Deliverables**:
- [ ] Syscall wrappers generated
- [ ] Bionic compiles successfully

---

### 2.2 Create NESM Header

**File**: `bionic/libc/include/sys/nesm.h`

```c
#ifndef _SYS_NESM_H
#define _SYS_NESM_H

#include <sys/types.h>
#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Network Event Stream Model (NESM)
 *
 * Push-based network event delivery mechanism.
 * Reduces syscall overhead and improves power efficiency.
 */

#define NESM_MAX_EVENT_SIZE 2048

/* Protocol masks for nesm_register() */
#define NESM_PROTO_TCP  (1 << IPPROTO_TCP)
#define NESM_PROTO_UDP  (1 << IPPROTO_UDP)
#define NESM_PROTO_RAW  (1 << IPPROTO_RAW)
#define NESM_PROTO_ALL  0xFFFFFFFF

/* NESM event structure */
struct nesm_event {
    int fd;               /* Socket file descriptor */
    int protocol;         /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    size_t len;          /* Packet length */
    unsigned char data[NESM_MAX_EVENT_SIZE];  /* Packet data */
};

/**
 * Register a socket for NESM event delivery
 *
 * @param sockfd Socket file descriptor
 * @param proto_mask Bitmask of protocols (NESM_PROTO_*)
 * @return 0 on success, -1 on error (errno set)
 */
int nesm_register(int sockfd, unsigned long proto_mask);

/**
 * Wait for network events
 *
 * Blocks until events are available or timeout expires.
 * Returns all available events up to max_events.
 *
 * @param events Array to receive events
 * @param max_events Maximum events to return
 * @param timeout_ms Timeout in milliseconds (-1 = infinite)
 * @return Number of events, 0 on timeout, -1 on error
 */
int nesm_wait(struct nesm_event *events, size_t max_events, int timeout_ms);

/**
 * Control NESM behavior
 *
 * @param cmd Control command
 * @param arg Command argument
 * @return 0 on success, -1 on error
 */
int nesm_ctl(int cmd, unsigned long arg);

/**
 * Unregister a socket from NESM
 *
 * @param sockfd Socket file descriptor
 * @return 0 on success, -1 on error
 */
int nesm_unregister(int sockfd);

/* NESM control commands */
#define NESM_CTL_SET_QUEUE_SIZE   1
#define NESM_CTL_GET_STATS        2

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NESM_H */
```

**Deliverables**:
- [ ] Header file created
- [ ] Documentation complete
- [ ] Compiles without errors

---

### 2.3 Create Test Program

**File**: `bionic/tests/nesm_test.cpp`

```cpp
#include <gtest/gtest.h>
#include <sys/nesm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

TEST(nesm, register_unregister) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sock, 0);

    int ret = nesm_register(sock, NESM_PROTO_UDP);
    EXPECT_EQ(ret, 0);

    ret = nesm_unregister(sock);
    EXPECT_EQ(ret, 0);

    close(sock);
}

TEST(nesm, receive_udp_packet) {
    // Create and bind UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sock, 0);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    ASSERT_EQ(bind(sock, (struct sockaddr*)&addr, sizeof(addr)), 0);

    // Register with NESM
    ASSERT_EQ(nesm_register(sock, NESM_PROTO_UDP), 0);

    // Send test packet
    int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    const char *msg = "test message";
    sendto(send_sock, msg, strlen(msg), 0,
           (struct sockaddr*)&addr, sizeof(addr));

    // Receive via NESM
    struct nesm_event events[10];
    int n = nesm_wait(events, 10, 1000);  // 1 second timeout

    EXPECT_EQ(n, 1);
    EXPECT_EQ(events[0].fd, sock);
    EXPECT_EQ(events[0].protocol, IPPROTO_UDP);
    EXPECT_EQ(events[0].len, strlen(msg));
    EXPECT_EQ(memcmp(events[0].data, msg, strlen(msg)), 0);

    close(send_sock);
    close(sock);
}
```

**Deliverables**:
- [ ] Test suite created
- [ ] Tests pass on device
- [ ] Coverage for basic functionality

---

## Phase 3: Android Framework Integration (2-3 weeks)

### 3.1 SocketInputStream with NESM

**Option A**: Transparent replacement in libcore

**File**: `libcore/ojluni/src/main/native/SocketInputStream.c`

```c
// Add NESM support alongside existing implementation
static jint SocketInputStream_socketRead(JNIEnv *env, jobject this,
                                         jint fd, jbyteArray data,
                                         jint off, jint len, jint timeout)
{
    // Try NESM first
    if (nesm_is_registered(fd)) {
        struct nesm_event event;
        int ret = nesm_wait(&event, 1, timeout);
        if (ret > 0 && event.fd == fd) {
            (*env)->SetByteArrayRegion(env, data, off,
                                      min(len, event.len),
                                      (jbyte*)event.data);
            return min(len, event.len);
        }
    }

    // Fallback to traditional read()
    return traditional_socket_read(env, this, fd, data, off, len, timeout);
}
```

**Option B**: New NESM-specific Java API

```java
// frameworks/base/core/java/android/net/NetworkEventStream.java
package android.net;

public class NetworkEventStream {

    private static class Event {
        public int fd;
        public int protocol;
        public byte[] data;
    }

    public static native void register(int sockfd, int protoMask);
    public static native Event[] wait(int maxEvents, int timeoutMs);
    public static native void unregister(int sockfd);

    static {
        System.loadLibrary("nesm_jni");
    }
}
```

**Deliverables**:
- [ ] JNI bindings created
- [ ] Java API documented
- [ ] Basic socket integration working

---

### 3.2 ConnectivityService Integration

**File**: `frameworks/base/services/core/java/com/android/server/ConnectivityService.java`

```java
public class ConnectivityService extends IConnectivityManager.Stub {

    private void enableNetworkESM() {
        // Auto-enable NESM for background apps
        for (Network network : getAllNetworks()) {
            NetworkCapabilities caps = getNetworkCapabilities(network);

            if (isBackgroundTraffic(caps)) {
                // Enable aggressive batching for background
                NetworkEventStream.setPolicy(network,
                    /* batch_size */ 10,
                    /* timeout_ms */ 1000);
            }
        }
    }
}
```

**Deliverables**:
- [ ] Policy framework created
- [ ] Background/foreground classification
- [ ] Power-aware configuration

---

### 3.3 DNS Resolver (Priority Target)

DNS is perfect for NESM - small UDP packets, high frequency.

**File**: `system/netd/resolv/res_send.cpp`

```cpp
int res_nsend_nesm(res_state statp, const u_char* buf, int buflen,
                   u_char* ans, int anssiz)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    // Register with NESM
    nesm_register(sock, NESM_PROTO_UDP);

    // Send DNS query
    sendto(sock, buf, buflen, 0, ...);

    // Wait for response via NESM (no polling!)
    struct nesm_event events[1];
    int n = nesm_wait(events, 1, 5000);  // 5 second timeout

    if (n > 0 && events[0].fd == sock) {
        memcpy(ans, events[0].data, min(anssiz, events[0].len));
        close(sock);
        return events[0].len;
    }

    close(sock);
    return -1;
}
```

**Deliverables**:
- [ ] DNS resolver using NESM
- [ ] DNS queries working correctly
- [ ] Measurable latency improvement

---

## Phase 4: TCP Support (2-3 weeks)

### 4.1 TCP Integration

**Hook Point**: `net/ipv4/tcp_input.c` in `tcp_data_queue()`

```c
// net/ipv4/tcp_input.c

static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
    // ... existing TCP processing ...

    // NESM: Push data to event stream
    if (sk->sk_socket && sk->sk_socket->file) {
        nesm_push_packet(sk->sk_socket, skb);
    }

    // Continue with normal processing
    ...
}
```

**Challenge**: TCP is stream-oriented, not packet-oriented

**Solution**: Define "event" as "data available" with configurable threshold

```c
struct nesm_socket {
    // ... existing fields ...

    // TCP-specific
    size_t tcp_threshold;  // Minimum bytes before event
    bool tcp_push_flag;    // Deliver on PSH flag
};
```

**Deliverables**:
- [ ] TCP packets delivered via NESM
- [ ] Stream semantics preserved
- [ ] HTTP requests work correctly

---

### 4.2 TCP Optimization

**Problem**: Many small TCP segments = many events

**Solution**: Smart coalescing

```c
bool should_deliver_tcp_event(struct nesm_socket *nsock)
{
    size_t queued = atomic_read(&nsock->queue_size_bytes);

    // Deliver if:
    // 1. Threshold reached
    if (queued >= nsock->tcp_threshold)
        return true;

    // 2. PSH flag set (end of message)
    if (nsock->tcp_push_flag)
        return true;

    // 3. Timeout since last delivery (prevent stalls)
    if (ktime_ms_delta(ktime_get(), nsock->last_delivery) > 50)
        return true;

    return false;
}
```

**Deliverables**:
- [ ] TCP coalescing implemented
- [ ] Configurable thresholds
- [ ] No application stalls

---

## Phase 5: Power Management (1-2 weeks)

### 5.1 Power-Aware Policies

**File**: `kernel/nesm.c`

```c
enum nesm_power_class {
    NESM_POWER_REALTIME,     // VoIP, gaming - immediate delivery
    NESM_POWER_INTERACTIVE,  // Messaging - balanced
    NESM_POWER_BACKGROUND,   // Sync - aggressive batching
};

struct nesm_power_policy {
    enum nesm_power_class class;
    unsigned int min_batch_size;
    unsigned int max_latency_ms;
    bool coalesce_with_screen_on;
};

void nesm_set_power_policy(struct nesm_socket *nsock,
                           struct nesm_power_policy *policy)
{
    spin_lock(&nsock->lock);
    nsock->power_policy = *policy;
    spin_unlock(&nsock->lock);
}
```

**Integration with Android Power Manager**:

```java
// frameworks/base PowerManager integration
public void setNetworkPowerPolicy(int sockfd, int powerClass) {
    switch (powerClass) {
        case POWER_CLASS_BACKGROUND:
            NetworkEventStream.setPolicy(sockfd,
                /* min_batch */ 10,
                /* max_latency_ms */ 2000);
            break;
        case POWER_CLASS_INTERACTIVE:
            NetworkEventStream.setPolicy(sockfd,
                /* min_batch */ 3,
                /* max_latency_ms */ 100);
            break;
    }
}
```

**Deliverables**:
- [ ] Power policy framework
- [ ] Android integration
- [ ] Per-app power classification

---

### 5.2 Doze Mode Integration

**File**: `frameworks/base/services/core/java/com/android/server/DeviceIdleController.java`

```java
private void enterDozeMode() {
    // Configure NESM for extreme power savings
    NetworkEventStream.setGlobalPolicy(
        /* defer_all_events */ true,
        /* wakeup_only_for_priority */ true);

    // Only high-priority push notifications wake device
}
```

**Deliverables**:
- [ ] Doze mode compatibility
- [ ] No unnecessary wakeups
- [ ] Priority event handling

---

## Phase 6: Testing & Validation (2 weeks)

### 6.1 Functional Testing

**Test Cases**:

```bash
# UDP echo test
echo "test" | nc -u localhost 12345

# TCP HTTP request
curl http://localhost:8080/test

# Multiple concurrent connections
ab -n 1000 -c 10 http://localhost:8080/

# DNS resolution
nslookup google.com

# Stress test
iperf3 -c localhost -u -b 100M -t 60
```

**Deliverables**:
- [ ] All protocols working
- [ ] No packet loss
- [ ] No regressions

---

### 6.2 Performance Measurement

**Metrics to Measure**:

1. **Syscall Reduction**:
```bash
strace -c -p $(pidof system_server) & sleep 60; killall strace
# Compare: epoll_wait + read calls vs nesm_wait calls
```

2. **CPU Usage**:
```bash
top -p $(pidof system_server)
# Measure CPU % during network activity
```

3. **Power Consumption**:
```bash
adb shell dumpsys batterystats --reset
# Use device for 30 minutes
adb shell dumpsys batterystats
# Compare mAh consumed
```

4. **Latency**:
```bash
# Measure time from packet arrival to app processing
# Use ftrace or similar tools
```

**Target Metrics**:
- [ ] 40-60% reduction in syscalls
- [ ] 10-20% reduction in CPU usage
- [ ] 15-30% improvement in battery life (network-heavy workload)
- [ ] <5% latency overhead

---

### 6.3 Regression Testing

**Critical Tests**:
- [ ] All CTS (Compatibility Test Suite) tests pass
- [ ] All VTS (Vendor Test Suite) tests pass
- [ ] No ANR (Application Not Responding) issues
- [ ] No network connectivity regressions
- [ ] VoIP calls work correctly
- [ ] Video streaming works
- [ ] Gaming latency acceptable

---

## Phase 7: Documentation & Cleanup (1 week)

### 7.1 Code Documentation

- [ ] Kernel API documentation
- [ ] Userspace API documentation
- [ ] Integration guide for apps
- [ ] Performance tuning guide

### 7.2 Create Patches

```bash
# Generate final patches
cd kernel_redbull_source
git format-patch android-12.0.0_r3..nesm -o ~/patches/nesm/

cd bionic
git format-patch android-12.0.0_r3..nesm -o ~/patches/nesm/

cd frameworks/base
git format-patch android-12.0.0_r3..nesm -o ~/patches/nesm/
```

**Deliverables**:
- [ ] All patches generated
- [ ] Patches apply cleanly
- [ ] Documentation complete

---

## Success Criteria Summary

### Phase 1 (Kernel)
✅ NESM driver loads successfully
✅ UDP packets delivered via NESM
✅ No kernel panics or memory leaks
✅ Basic userspace test program works

### Phase 2 (Bionic)
✅ Syscalls accessible from C/C++
✅ Header files compile
✅ Unit tests pass

### Phase 3 (Framework)
✅ Java apps can use NESM
✅ DNS resolver uses NESM
✅ No application breakage

### Phase 4 (TCP)
✅ TCP connections work via NESM
✅ HTTP requests successful
✅ No connection stalls

### Phase 5 (Power)
✅ Power policies configurable
✅ Doze mode integration working
✅ Measurable power savings

### Phase 6 (Testing)
✅ All tests pass
✅ Performance targets met
✅ No regressions

### Phase 7 (Documentation)
✅ Complete documentation
✅ Patches ready for distribution

---

## Risk Mitigation

### High Risk Items

1. **TCP Stream Semantics**
   - Risk: Breaking application assumptions about stream delivery
   - Mitigation: Extensive testing with real apps (Chrome, Gmail)

2. **Memory Consumption**
   - Risk: Queue sizes too large, OOM
   - Mitigation: Strict queue limits, flow control

3. **Race Conditions**
   - Risk: Concurrent access to queues
   - Mitigation: Careful locking, lockdep testing

4. **Performance Regression**
   - Risk: Overhead worse than epoll for some workloads
   - Mitigation: Fallback mechanism, per-socket enable/disable

---

## Timeline Summary

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| 1. Kernel Core | 2-3 weeks | None |
| 2. Bionic | 1 week | Phase 1 |
| 3. Framework | 2-3 weeks | Phase 2 |
| 4. TCP Support | 2-3 weeks | Phase 1 |
| 5. Power Management | 1-2 weeks | Phase 3, 4 |
| 6. Testing | 2 weeks | All previous |
| 7. Documentation | 1 week | Phase 6 |

**Total**: 8-12 weeks for production-ready implementation

---

## Next Steps

1. **Immediate**: Set up development branch
   ```bash
   cd kernel_redbull_source
   git checkout -b nesm-development
   ```

2. **Week 1**: Implement NESM core (nesm.c skeleton)

3. **Week 2**: Implement nesm_register() and nesm_wait()

4. **Week 3**: UDP integration and basic testing

Ready to start Phase 1?
