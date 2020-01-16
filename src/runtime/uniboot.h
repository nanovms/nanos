#pragma once

#include <predef.h>

#ifdef BOOT

#include <def32.h>

#else /* BOOT */

#include <def64.h>
#define user_va_tag_offset 44
#ifdef STAGE3
#define va_tag_offset 40        /* 1TB */
#else
#define va_tag_offset user_va_tag_offset
#endif

static inline void* tag(void* v, u64 tval) {
  return pointer_from_u64((tval << va_tag_offset) | u64_from_pointer(v));
}

static inline u16 tagof(void* v) {
  return (u64_from_pointer(v) >> va_tag_offset);
}

#define valueof(__x) (__x)

#endif /* BOOT */

/* needed for physical region allocator, before we ever look at the
   elf - be sure that this matches the stage3 linker script
   (TODO: build time assert) */
#define KERNEL_RESERVE_START 0x7f000000
#define KERNEL_RESERVE_END   0x80000000

extern void * AP_BOOT_PAGE;

/* AP boot page */
#define AP_BOOT_START u64_from_pointer(&AP_BOOT_PAGE)
#define AP_BOOT_END (AP_BOOT_START + PAGESIZE)

/* identity-mapped space for page tables - we can shrink this if we
   ever make the page table code aware of mappings (e.g. virt_from_phys) */
#define IDENTITY_HEAP_SIZE (128 * MB)

/* the stage2 secondary working heap - this needs to be large enough
   to accomodate all tfs allocations when loading the kernel - it gets
   recycled in stage3, so be generous */
#define STAGE2_WORKING_HEAP_SIZE (128 * MB)

/* maximum buckets that can fit within a PAGESIZE_2M mcache */
#define TABLE_MAX_BUCKETS 131072

/* runloop timer minimum and maximum */
#define RUNLOOP_TIMER_MAX_PERIOD_US     100000
#define RUNLOOP_TIMER_MIN_PERIOD_US     10

/* XXX just for initial mp bringup... */
#define MAX_CPUS 16

/* could probably find progammatically via cpuid... */
#define DEFAULT_CACHELINE_SIZE 64

#include <x86.h>
