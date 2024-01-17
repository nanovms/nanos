/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2015-2020 Amazon.com, Inc. or its affiliates.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 * * Neither the name of copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ENA_PLAT_H_
#define ENA_PLAT_H_

#define __STRING(x)     #x
#define __XSTRING(x)    __STRING(x)

#define BITSET_DEFINE(t, _s)            \
    struct t {                          \
        u64 __bits[((_s) + 63) / 64];   \
    }

#define BIT_ZERO(_s, p) zero(p, sizeof(*p))

#define BIT_ISSET(_s, n, p)                                 \
    (((p)->__bits[(n) / 64] & (1 << ((n) % 64))) != 0)

#define BIT_SET_ATOMIC(_s, n, p)                        \
    atomic_set_bit(&((p)->__bits[(n) / 64]), (n) % 64)

#define BIT_CLR_ATOMIC(_s, n, p)                            \
    atomic_clear_bit(&((p)->__bits[(n) / 64]), (n) % 64)

typedef u64 uintptr_t;

/* Levels */
#define ENA_ALERT   (1 << 0) /* Alerts are providing more error info.     */
#define ENA_WARNING (1 << 1) /* Driver output is more error sensitive.    */
#define ENA_INFO    (1 << 2) /* Provides additional driver info. 	      */
#define ENA_DBG     (1 << 3) /* Driver output for debugging.	      */
/* Detailed info that will be printed with ENA_INFO or ENA_DEBUG flag. 	      */
#define ENA_TXPTH   (1 << 4) /* Allows TX path tracing. 		      */
#define ENA_RXPTH   (1 << 5) /* Allows RX path tracing.		      */
#define ENA_RSC     (1 << 6) /* Goes with TXPTH or RXPTH, free/alloc res. */
#define ENA_IOQ     (1 << 7) /* Detailed info about IO queues. 	      */
#define ENA_ADMQ    (1 << 8) /* Detailed info about admin queue. 	      */
#define ENA_NETMAP  (1 << 9) /* Detailed info about netmap. 	      */

#define DEFAULT_ALLOC_ALIGNMENT 8

#define ena_log_level   (ENA_ALERT | ENA_WARNING)

#define container_of(ptr, type, member)                         \
    ({                                                          \
        const __typeof(((type *)0)->member) *__p = (ptr);       \
        (type *)((uintptr_t)__p - offsetof(type *, member));    \
    })

#define ena_trace_raw(ctx, level, fmt, args...)     \
    do {                                            \
        ((void)(ctx));                              \
        if (((level) & ena_log_level) == (level))   \
            rprintf(fmt, ##args);                   \
    } while (0)

#define ena_trace(ctx, level, fmt, args...)                     \
    ena_trace_raw(ctx, level, "%s(): " fmt, func_ss, ##args)

#define ena_trc_dbg(ctx, format, arg...)    \
    ena_trace(ctx, ENA_DBG, format, ##arg)
#define ena_trc_info(ctx, format, arg...)   \
    ena_trace(ctx, ENA_INFO, format, ##arg)
#define ena_trc_warn(ctx, format, arg...)   \
    ena_trace(ctx, ENA_WARNING, format, ##arg)
#define ena_trc_err(ctx, format, arg...)    \
    ena_trace(ctx, ENA_ALERT, format, ##arg)

#define device_printf(dev, fmt, args...)    \
    do {                                    \
        ((void)(dev));                      \
        rprintf(fmt, ##args);               \
    } while (0)

#define unlikely(x) !!(x)
#define likely(x)   !!(x)

#define __iomem volatile
#define ____cacheline_aligned   __attribute__((aligned(64)))

#define MAX_ERRNO   4095
#define IS_ERR_VALUE(x) unlikely((x) <= (unsigned long)MAX_ERRNO)

#define ENA_WARN(cond, ctx, format, arg...)     \
    do {                                        \
        if (unlikely((cond))) {                 \
            ena_trc_warn(ctx, format, ##arg);   \
        }                                       \
    } while (0)

static inline long IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((unsigned long )ptr);
}

static inline void *ERR_PTR(long error)
{
    return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
    return (long)ptr;
}

#define GENMASK(h, l)       (((~0U) - (1U << (l)) + 1) & (~0U >> (32 - 1 - (h))))
#define GENMASK_ULL(h, l)   (((~0ULL) << (l)) & (~0ULL >> (64 - 1 - (h))))
#define BIT(x)              (1UL << (x))

#define SZ_256  (256)
#define SZ_4K   (4096)

#define	ENA_COM_OK              0
#define ENA_COM_FAULT           14
#define	ENA_COM_INVAL           22
#define ENA_COM_NO_MEM          12
#define	ENA_COM_NO_SPACE        28
#define ENA_COM_TRY_AGAIN       -1
#define	ENA_COM_UNSUPPORTED     95
#define	ENA_COM_NO_DEVICE       19
#define ENA_COM_TIMER_EXPIRED   110
#define ENA_COM_EIO             5

#define ENA_MSLEEP(x)   kernel_delay(milliseconds(x))
#define ENA_USLEEP(x)   kernel_delay(microseconds(x))
#define ENA_UDELAY(x)   kernel_delay(microseconds(x))
#define ENA_GET_SYSTEM_TIMEOUT(timeout_us)                          \
    (usec_from_timestamp(now(CLOCK_ID_MONOTONIC)) + (timeout_us))
#define ENA_TIME_EXPIRE(timeout)                                            \
    ((s64)(usec_from_timestamp(now(CLOCK_ID_MONOTONIC)) - timeout) >= 0)
#define ENA_MIGHT_SLEEP()

#define min_t(type, _x, _y) ((type)(_x) < (type)(_y) ? (type)(_x) : (type)(_y))
#define max_t(type, _x, _y) ((type)(_x) > (type)(_y) ? (type)(_x) : (type)(_y))

#define ENA_MIN32(x,y)  MIN(x, y)
#define ENA_MIN16(x,y)  MIN(x, y)
#define ENA_MIN8(x,y)   MIN(x, y)

#define ENA_MAX32(x,y)  MAX(x, y)
#define ENA_MAX16(x,y)  MAX(x, y)
#define ENA_MAX8(x,y)   MAX(x, y)

/* Spinlock related methods */
#define ena_spinlock_t  struct spinlock
#define ENA_SPINLOCK_INIT(spinlock) spin_lock_init(&(spinlock))
#define ENA_SPINLOCK_DESTROY(spinlock)
#define ENA_SPINLOCK_LOCK(spinlock, flags)  flags = spin_lock_irq(&(spinlock))
#define ENA_SPINLOCK_UNLOCK(spinlock, flags)    spin_unlock_irq(&(spinlock), flags)

#define dma_addr_t  u64

typedef struct {
    u64 paddr;
    void *vaddr;
    u64 size;
} ena_mem_handle_t;

struct ena_bus {
    struct pci_bar *reg_bar;
};

typedef boolean bool;

typedef u8 uint8_t;
typedef u32 uint32_t;
typedef u32 ena_atomic32_t;
typedef u64 uint64_t;

#define ENA_PRIu64 "ld"

typedef u64 ena_time_t;
typedef struct ifnet ena_netdev;

struct ena_adapter;

int ena_dma_alloc(struct ena_adapter *adapter, u64 size, ena_mem_handle_t *dma, int mapflags,
                  u64 alignment);

static inline u32 ena_reg_read32(struct ena_bus *bus, u64 offset)
{
    u32 v = pci_bar_read_4(bus->reg_bar, offset);
    read_barrier();
    return v;
}

#define ENA_MEMCPY_TO_DEVICE_64(dst, src, size)             \
    do {                                                    \
        int count, i;                                       \
        volatile uint64_t *to = (volatile uint64_t *)(dst); \
        const uint64_t *from = (const uint64_t *)(src);     \
        count = (size) / 8;                                 \
        for (i = 0; i < count; i++, from++, to++)           \
            *to = *from;                                    \
    } while (0)

#define ENA_MEM_ALLOC(dmadev, size)                                 \
    allocate_zero(((struct ena_adapter *)(dmadev))->general, size)
#define ENA_MEM_ALLOC_NODE(dmadev, size, virt, node, dev_node)  virt = NULL
#define ENA_MEM_FREE(dmadev, ptr, size)                                 \
    deallocate(((struct ena_adapter *)(dmadev))->general, ptr, size)
#define ENA_MEM_ALLOC_COHERENT_NODE_ALIGNED(dmadev, size, virt, phys,	\
    handle, node, dev_node, alignment)  \
    do {                                \
        ((virt) = NULL);                \
        (void)(dev_node);               \
    } while (0)

#define ENA_MEM_ALLOC_COHERENT_NODE(dmadev, size, virt, phys, handle, node, dev_node)   \
    ENA_MEM_ALLOC_COHERENT_NODE_ALIGNED(dmadev, size, virt,                             \
        phys, handle, node, dev_node, DEFAULT_ALLOC_ALIGNMENT)

#define ENA_MEM_ALLOC_COHERENT_ALIGNED(dmadev, size, virt, phys, dma, alignment)    \
    do {                                                                            \
        ena_dma_alloc((dmadev), (size), &(dma), 0, alignment);                      \
        (virt) = (void *)(dma).vaddr;                                               \
        (phys) = (dma).paddr;                                                       \
    } while (0)

#define ENA_MEM_ALLOC_COHERENT(dmadev, size, virt, phys, dma)                               \
    ENA_MEM_ALLOC_COHERENT_ALIGNED(dmadev, size, virt, phys, dma, DEFAULT_ALLOC_ALIGNMENT)

#define ENA_MEM_FREE_COHERENT(dmadev, siz, virt, phys, dma) \
    do {                                                    \
        (void)siz;                                          \
        deallocate((dmadev)->contiguous, virt, (dma).size); \
        (virt) = NULL;                                      \
    } while (0)

/* Register R/W methods */
#define ENA_REG_WRITE32(bus, value, offset)             \
    do {                                                \
        write_barrier();                                \
        ENA_REG_WRITE32_RELAXED(bus, value, offset);    \
    } while (0)

#define ENA_REG_WRITE32_RELAXED(bus, value, offset)                             \
    pci_bar_write_4(((struct ena_bus *)bus)->reg_bar, (u64)(offset), (value))

#define ENA_REG_READ32(bus, offset)                         \
    ena_reg_read32((struct ena_bus *)(bus), (u64)(offset))

#define ENA_DB_SYNC_WRITE(mem_handle)   write_barrier()
#define ENA_DB_SYNC_PREREAD(mem_handle)
#define ENA_DB_SYNC_POSTREAD(mem_handle)
#define ENA_DB_SYNC(mem_handle) ENA_DB_SYNC_WRITE(mem_handle)

#define CSUM_OFFLOAD    (CSUM_IP|CSUM_TCP|CSUM_UDP)

#define prefetch(x)     (void)(x)
#define prefetchw(x)    (void)(x)

#define ATOMIC32_INC(I32_PTR)       fetch_and_add_32(I32_PTR, 1)
#define ATOMIC32_DEC(I32_PTR)       fetch_and_add_32(I32_PTR, -1)
#define ATOMIC32_READ(I32_PTR)      (*(I32_PTR))
#define ATOMIC32_SET(I32_PTR, VAL)  *(I32_PTR) = (VAL)

#define	barrier() __asm__ __volatile__("": : :"memory")
#define dma_rmb() barrier()
#define mmiowb() barrier()

#define	ACCESS_ONCE(x)  (*(volatile __typeof(x) *)&(x))
#define READ_ONCE(x)    ({      \
        __typeof(x) __var;      \
        barrier();              \
        __var = ACCESS_ONCE(x); \
        barrier();              \
        __var;                  \
    })
#define READ_ONCE8(x) READ_ONCE(x)
#define READ_ONCE16(x) READ_ONCE(x)
#define READ_ONCE32(x) READ_ONCE(x)

#define upper_32_bits(n)    ((uint32_t)(((n) >> 16) >> 16))
#define lower_32_bits(n)    ((uint32_t)(n))

#define DIV_ROUND_UP(n, d)  (((n) + (d) - 1) / (d))

#define ENA_FFS __builtin_ffs

void ena_rss_key_fill(void *key, size_t size);

#define ENA_RSS_FILL_KEY(key, size) ena_rss_key_fill(key, size)

#include "ena_defs/ena_includes.h"

#endif /* ENA_PLAT_H_ */
