/*-
 * BSD LICENSE
 *
 * Copyright (c) 2015-2019 Amazon.com, Inc. or its affiliates.
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

#include "ena_internal.h"

#if 0
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>

#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/eventhandler.h>
#include <sys/types.h>
#include <sys/timetc.h>
#include <sys/cdefs.h>

#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/in_cksum.h>
#include <machine/pcpu.h>
#include <machine/resource.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_lro.h>
#include <netinet/udp.h>

#include <dev/led/led.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#endif

extern struct ena_bus_space ebs;

/* Levels */
#define ENA_ALERT     (1 << 0) /* Alerts are providing more error info.     */
#define ENA_WARNING     (1 << 1) /* Driver output is more error sensitive.    */
#define ENA_INFO     (1 << 2) /* Provides additional driver info.           */
#define ENA_DBG     (1 << 3) /* Driver output for debugging.          */
/* Detailed info that will be printed with ENA_INFO or ENA_DEBUG flag.           */
#define ENA_TXPTH     (1 << 4) /* Allows TX path tracing.               */
#define ENA_RXPTH     (1 << 5) /* Allows RX path tracing.              */
#define ENA_RSC     (1 << 6) /* Goes with TXPTH or RXPTH, free/alloc res. */
#define ENA_IOQ     (1 << 7) /* Detailed info about IO queues.           */
#define ENA_ADMQ    (1 << 8) /* Detailed info about admin queue.           */
#define ENA_NETMAP    (1 << 9) /* Detailed info about netmap.           */

extern int ena_log_level;

#ifdef ENA_DEBUG
#define ena_trace_raw(level, fmt, args...)            \
    do {                                              \
        if (((level) & ena_log_level) != (level))     \
            break;                                    \
        rprintf(fmt, ##args);                         \
    } while (0)
#else
#define ena_trace_raw(level, fmt, args...)
#endif

#define ena_trace(level, fmt, args...)                \
    ena_trace_raw(level, "ENA: %s(): "                \
        fmt, __func__, ##args)

#define ena_trc_dbg(format, arg...)     ena_trace(ENA_DBG, format, ##arg)
#define ena_trc_info(format, arg...)     ena_trace(ENA_INFO, format, ##arg)
#define ena_trc_warn(format, arg...)     ena_trace(ENA_WARNING, format, ##arg)
#define ena_trc_err(format, arg...)     ena_trace(ENA_ALERT, format, ##arg)

#define unlikely(x)    (x)
#define likely(x)      (x)

// TODO: move to common place iwth hyperv code
#define CACHE_LINE_SHIFT        6
#define CACHE_LINE_SIZE         (1 << CACHE_LINE_SHIFT)

#define __iomem
#define ____cacheline_aligned __aligned(CACHE_LINE_SIZE)
#define __aligned(size) __attribute__((aligned(size)))

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) <= (unsigned long)MAX_ERRNO)

#define ENA_ASSERT(cond, format, arg...)                \
    do {                                \
        if (unlikely(!(cond))) {                \
            ena_trc_err(                    \
                "Assert failed on %s:%s:%d:" format,    \
                __FILE__, __func__, __LINE__, ##arg);    \
        }                            \
    } while (0)

#define ENA_WARN(cond, format, arg...)                    \
    do {                                \
        if (unlikely((cond))) {                    \
            ena_trc_warn(format, ##arg);            \
        }                            \
    } while (0)

static inline long IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((unsigned long)ptr);
}

static inline void *ERR_PTR(long error)
{
    return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
    return (long) ptr;
}

#define GENMASK(h, l)    (((~0U) - (1U << (l)) + 1) & (~0U >> (32 - 1 - (h))))
#define GENMASK_ULL(h, l)    (((~0ULL) << (l)) & (~0ULL >> (64 - 1 - (h))))
#define BIT(x)            (1UL << (x))

#define ENA_ABORT()         BUG()
#define BUG()             panic("ENA BUG")

#define SZ_256            (256)
#define SZ_4K            (4096)

#define    ENA_COM_OK        0
#define ENA_COM_FAULT        EFAULT
#define    ENA_COM_INVAL        EINVAL
#define ENA_COM_NO_MEM        ENOMEM
#define    ENA_COM_NO_SPACE    ENOSPC
#define ENA_COM_TRY_AGAIN    -1
#define    ENA_COM_UNSUPPORTED    EOPNOTSUPP
#define    ENA_COM_NO_DEVICE    ENODEV
#define    ENA_COM_PERMISSION    EPERM
#define ENA_COM_TIMER_EXPIRED    ETIMEDOUT

// TODO
//#define ENA_MSLEEP(x)         pause_sbt("ena", SBT_1MS * (x), SBT_1MS, 0)
#define ENA_MSLEEP(x)         kernel_delay(milliseconds(x))
#define ENA_UDELAY(x)         kernel_delay(microseconds(x))
#define ENA_GET_SYSTEM_TIMEOUT(timeout_us) \
    ((long)usec_from_timestamp(now(CLOCK_ID_MONOTONIC)) + (timeout_us))
#define ENA_TIME_EXPIRE(timeout)  (timeout < usec_from_timestamp(now(CLOCK_ID_MONOTONIC)))
#define ENA_MIGHT_SLEEP()

#define min_t(type, _x, _y) ((type)(_x) < (type)(_y) ? (type)(_x) : (type)(_y))
#define max_t(type, _x, _y) ((type)(_x) > (type)(_y) ? (type)(_x) : (type)(_y))

#define ENA_MIN32(x,y)     MIN(x, y)
#define ENA_MIN16(x,y)    MIN(x, y)
#define ENA_MIN8(x,y)    MIN(x, y)

#define ENA_MAX32(x,y)     MAX(x, y)
#define ENA_MAX16(x,y)     MAX(x, y)
#define ENA_MAX8(x,y)     MAX(x, y)

/* Spinlock related methods */
// TODO!!
#define ena_spinlock_t     struct spinlock
#define ENA_SPINLOCK_INIT(spinlock)                \
    spin_lock_init(&(spinlock))
#define ENA_SPINLOCK_DESTROY(spinlock)
#define ENA_SPINLOCK_LOCK(spinlock, flags)            \
    do {                            \
        (void)(flags);                    \
        spin_lock(&(spinlock));            \
    } while (0)
#define ENA_SPINLOCK_UNLOCK(spinlock, flags)            \
    do {                            \
        (void)(flags);                    \
        spin_unlock(&(spinlock));            \
    } while (0)


/* Wait queue related methods */
//#define ena_wait_event_t struct { struct cv wq; struct mtx mtx; }
#define ena_wait_event_t struct { volatile boolean raised; struct spinlock lock; }
#define ENA_WAIT_EVENT_INIT(waitqueue)                    \
    do {                                \
        (waitqueue).raised = 0;         \
        spin_lock_init(&(waitqueue).lock);            \
    } while (0)
#define ENA_WAIT_EVENT_DESTROY(waitqueue)                \
    do {                                \
    } while (0)
#define ENA_WAIT_EVENT_CLEAR(waitqueue)                    \
    (waitqueue).raised = 0;
#define ENA_WAIT_EVENT_WAIT(waitqueue, timeout_us)            \
    do {                                \
        for (int i = 0; (i < 10) && !(waitqueue).raised; ++i) {      \
            ENA_UDELAY(timeout_us/10);      \
        }                                   \
    /*  TODO!   \
        mtx_lock(&((waitqueue).mtx));                \
        cv_timedwait(&((waitqueue).wq), &((waitqueue).mtx),    \
            timeout_us * hz / 1000 / 1000 );            \
        mtx_unlock(&((waitqueue).mtx));                \
        */   \
    } while (0)
#define ENA_WAIT_EVENT_SIGNAL(waitqueue)        \
    do {                        \
        spin_lock(&((waitqueue).lock));        \
        (waitqueue).raised = true;    \
        spin_unlock(&((waitqueue).lock));        \
    } while (0)

typedef u64 bus_addr_t;
typedef char *caddr_t;
#define dma_addr_t    bus_addr_t
#if 0
#define u8         uint8_t
#define u16         uint16_t
#define u32         uint32_t
#define u64         uint64_t
#endif
#define uint8_t         u8
#define uint16_t        u16
#define uint32_t        u32
#define uint64_t        u64
#define bool        boolean
#define size_t        unsigned long

typedef struct {
    bus_addr_t              paddr;
    caddr_t                 vaddr;
#if 0
        bus_dma_tag_t           tag;
    bus_dmamap_t            map;
        bus_dma_segment_t       seg;
#endif
    int                     nseg;
} ena_mem_handle_t;

#if 0
struct ena_bus {
    bus_space_handle_t     reg_bar_h;
    bus_space_tag_t     reg_bar_t;
    bus_space_handle_t    mem_bar_h;
    bus_space_tag_t     mem_bar_t;
};
#endif
struct ena_bus {
    struct pci_bar* reg_bar_p;
    struct pci_bar* mem_bar_p;
};

typedef u32 ena_atomic32_t;

struct ena_adapter;
#if 0
void    ena_dmamap_callback(void *arg, bus_dma_segment_t *segs, int nseg,
    int error);
#endif
int    ena_dma_alloc(struct ena_adapter_pci* adapter, u64 size, ena_mem_handle_t *dma,
    int mapflags);
void ena_dma_free(struct ena_adapter_pci* adapter, void *virt, u64 size);

#define ENA_MEMCPY_TO_DEVICE_64(dst, src, size)                \
    do {                                \
        int count, i;                        \
        volatile uint64_t *to = (volatile uint64_t *)(dst);    \
        const uint64_t *from = (const uint64_t *)(src);        \
        count = (size) / 8;                    \
                                    \
        for (i = 0; i < count; i++, from++, to++)        \
            *to = *from;                    \
    } while (0)

#define ENA_MEM_ALLOC(dmadev, virt, size_field, size) \
    do {                                \
        ((size_field) = size);                    \
        virt = allocate_zero((dmadev)->general, size);    \
    } while (0)
#define ENA_MEM_ALLOC_NODE(dmadev, size, virt, node, dev_node) (virt = 0)
#define ENA_MEM_FREE(dmadev, ptr, size) deallocate((dmadev)->general, ptr, size)
#define ENA_MEM_ALLOC_COHERENT_NODE(dmadev, size, virt, phys, handle, node, \
    dev_node)                                \
    do {                                \
        ((virt) = 0);                    \
        (void)(dev_node);                    \
    } while (0)

#define ENA_MEM_ALLOC_COHERENT(dmadev, size, virt, phys, dma)        \
    do {                                \
        ena_dma_alloc((dmadev), (size), &(dma), 0);        \
        (virt) = (void *)(dma).vaddr;                \
        (phys) = (dma).paddr;                    \
    } while (0)

#define ENA_MEM_FREE_COHERENT(dmadev, size, virt, phys, dma)        \
    do {                                \
        ena_dma_free((dmadev), (virt), (size));  \
        (virt) = 0;                        \
    } while (0)

/* Register R/W methods */
#define ENA_REG_WRITE32(bus, value, offset)                \
    pci_bar_write_4(                        \
              ((struct ena_bus*)bus)->reg_bar_p,        \
              (u64)(offset), (value))
#define ENA_REG_WRITE32_RELAXED(bus, value, offset)            \
    ENA_REG_WRITE32(bus, value, offset)

#define ENA_REG_READ32(bus, offset)                    \
    pci_bar_read_4(                        \
             ((struct ena_bus*)bus)->reg_bar_p,        \
             (u64)(offset))

#define ENA_DB_SYNC_WRITE(mem_handle) bus_dmamap_sync(            \
    (mem_handle)->tag, (mem_handle)->map, BUS_DMASYNC_PREWRITE)
#define ENA_DB_SYNC_PREREAD(mem_handle) bus_dmamap_sync(        \
    (mem_handle)->tag, (mem_handle)->map, BUS_DMASYNC_PREREAD)
#define ENA_DB_SYNC_POSTREAD(mem_handle) bus_dmamap_sync(        \
    (mem_handle)->tag, (mem_handle)->map, BUS_DMASYNC_POSTREAD)
// TODO
//#define ENA_DB_SYNC(mem_handle) ENA_DB_SYNC_WRITE(mem_handle)
#define ENA_DB_SYNC(mem_handle)

#define time_after(a,b)    ((long)((unsigned long)(b) - (unsigned long)(a)) < 0)

#define VLAN_HLEN     sizeof(struct ether_vlan_header)
#define CSUM_OFFLOAD     (CSUM_IP|CSUM_TCP|CSUM_UDP)

#define prefetch(x)    (void)(x)
#define prefetchw(x)    (void)(x)

/* DMA buffers access */
#define    dma_unmap_addr(p, name)            ((p)->dma->name)
#define    dma_unmap_addr_set(p, name, v)        (((p)->dma->name) = (v))
#define    dma_unmap_len(p, name)            ((p)->name)
#define    dma_unmap_len_set(p, name, v)        (((p)->name) = (v))

#define memcpy_toio memcpy

#define ATOMIC32_INC(I32_PTR)        atomic_add32(I32_PTR, 1)
#define ATOMIC32_DEC(I32_PTR)         atomic_add32(I32_PTR, -1)
#define ATOMIC32_READ(I32_PTR)         atomic_load_acq32(I32_PTR)
#define ATOMIC32_SET(I32_PTR, VAL)     atomic_store_rel32(I32_PTR, VAL)

#define    barrier() __asm__ __volatile__("": : :"memory")
#define dma_rmb() barrier()
#define mmiowb() barrier()

#define    ACCESS_ONCE(x) (*(volatile __typeof(x) *)&(x))
#define READ_ONCE(x)  ({            \
            __typeof(x) __var;    \
            barrier();        \
            __var = ACCESS_ONCE(x);    \
            barrier();        \
            __var;            \
        })
#define READ_ONCE8(x) READ_ONCE(x)
#define READ_ONCE16(x) READ_ONCE(x)
#define READ_ONCE32(x) READ_ONCE(x)

#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((uint32_t)(n))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#include "ena_defs/ena_includes.h"

#endif /* ENA_PLAT_H_ */
