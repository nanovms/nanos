#ifndef _HYPERV_INTERNAL_H_
#define _HYPERV_INTERNAL_H_

#include <errno.h>

#include "ctassert.h"

#define _KERNEL

typedef s8 int8_t;
typedef u8 uint8_t;
typedef u16 uint16_t;
typedef s16 int16_t;
typedef u32 uint32_t;
typedef s32 int32_t;
typedef u64 uint64_t;
typedef s64 int64_t;

typedef boolean bool;

typedef unsigned long size_t;

typedef u64 bus_addr_t;
typedef int64_t sbintime_t;
typedef u64 vm_offset_t;

#ifndef UINT16_MAX
#define UINT16_MAX             (65535U)
#endif

#define __packed __attribute__((__packed__))
#define __aligned(size) __attribute__((aligned(size)))

#define __offsetof(type, field)  __builtin_offsetof(type, field)

/*
 * CACHE_LINE_SIZE is the compile-time maximum cache line size for an
 * architecture.  It should be used with appropriate caution.
 */
#define CACHE_LINE_SHIFT        6
#define CACHE_LINE_SIZE         (1 << CACHE_LINE_SHIFT)

#define ffsl(x) __builtin_ffsl(x)

struct hyperv_guid;

#define GUID_FMT "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define GUID_ARG(d)      d[3], d[2], d[1], d[0], d[5], d[4], d[7], d[6], d[8], d[9], \
        d[10], d[11], d[12], d[13], d[14], d[15]

typedef struct iovec {
    void *iov_base;
    u64 iov_len;
} *iovec;

struct hypercall_ctx {
    void *hc_addr;
    u64 hc_paddr;
};

typedef struct hv_device hv_device;
typedef void task_fn_t(void *context, int pending);
typedef uint64_t (*hyperv_tc64_t)(void);
closure_type(vmbus_device_probe, boolean, hv_device *dev, storage_attach attach, boolean *attached);

void register_vmbus_driver(const struct hyperv_guid *type, vmbus_device_probe probe);
void init_netvsc(kernel_heaps kh);
void init_storvsc(kernel_heaps kh);
boolean init_vmbus_et_timer(heap general, u32 hyperv_features, hyperv_tc64_t hyperv_tc64,
                            clock_timer *ct, thunk *per_cpu_init);
void init_vmbus_shutdown(kernel_heaps kh);

boolean hyperv_arch_detect(kernel_heaps kh);
void hypercall_create(struct hypercall_ctx *hctx);
u64 hypercall_md(volatile void *hc_addr, u64 in_val, u64 in_paddr, u64 out_paddr);

#if defined(__x86_64__)

#define hyperv_read_msr     read_msr
#define hyperv_write_msr    write_msr

#elif defined(__aarch64__)

u64 aarch64_hv_get_vreg(u32 msr);
void aarch64_hv_set_vreg(u32 msr, u64 val);

#define hyperv_read_msr     aarch64_hv_get_vreg
#define hyperv_write_msr    aarch64_hv_set_vreg

#endif

#endif //_HYPERV_INTERNAL_H_
