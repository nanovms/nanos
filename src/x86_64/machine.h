#ifdef BOOT

#if !defined(UEFI)
#include <def32.h>
#else
#include <def64.h>
#endif

#else
/* kernel or userland */
#include <def64.h>

#define KMEM_BASE   0xffff800000000000ull
#define USER_LIMIT  0x0000800000000000ull

static inline __attribute__((always_inline)) u8 is_immediate(value v)
{
    return ((word)v & 1) != 0;
}

static inline __attribute__((always_inline)) u8 is_immediate_integer(value v)
{
    return ((word)v & 0x3) == 1;
}

#ifdef KERNEL

#define VA_TAG_BASE   KMEM_BASE
#define VA_TAG_OFFSET 38
#define VA_TAG_WIDTH  8

/* not for immediates */
static inline __attribute__((always_inline)) void *tag(void* v, value_tag t) {
    return pointer_from_u64(VA_TAG_BASE | (((u64)t) << VA_TAG_OFFSET) | u64_from_pointer(v));
}

static inline __attribute__((always_inline)) value_tag tagof(void* v) {
    u64 x = u64_from_pointer(v);
    /* only ints now, bit 1 reserved for future immediate types */
    if (is_immediate_integer(v))
        return tag_integer;
    return (x >> VA_TAG_OFFSET) & ((1ull << VA_TAG_WIDTH) - 1);
}

#else

static inline void *tag(void *v, u8 tval)
{
    *((u8 *)v-1) = tval;
    return v;
}

static inline u8 tagof(void *v)
{
    if (is_immediate_integer(v))
        return tag_integer;
    return *((u8 *)v-1);
}

#endif
#endif

#define PAGELOG     12
#define PAGESIZE    U64_FROM_BIT(PAGELOG)
#define PAGEMASK    MASK(PAGELOG)

/* to appease UBSAN */
#define _IMMASK ((word)-1ull >> 2)

static inline __attribute__((always_inline)) void *tagged_immediate_unsigned(word n)
{
    return (void*)(((n & _IMMASK) << 2) | 1);
}

static inline __attribute__((always_inline)) void *tagged_immediate_signed(sword n)
{
    return (void*)(((n & _IMMASK) << 2) | 1);
}

static inline __attribute__((always_inline)) u64 u64_from_tagged_immediate(void *v)
{
    return (word)v >> 2;
}

static inline __attribute__((always_inline)) s64 s64_from_tagged_immediate(void *v)
{
    return (sword)v >> 2;
}

static inline __attribute__((always_inline)) void compiler_barrier(void)
{
    asm volatile("" ::: "memory");
}

static inline __attribute__((always_inline)) void write_barrier(void)
{
    asm volatile("sfence" ::: "memory");
}

static inline __attribute__((always_inline)) void read_barrier(void)
{
    asm volatile("lfence" ::: "memory");
}

static inline __attribute__((always_inline)) void memory_barrier(void)
{
    asm volatile("mfence" ::: "memory");
}

static inline __attribute__((always_inline)) word fetch_and_add(word *variable, word value)
{
    return __sync_fetch_and_add(variable, value);
}

static inline __attribute__((always_inline)) word fetch_and_add_32(u32 *variable, u32 value)
{
    return __sync_fetch_and_add(variable, value);
}

#define mk_atomic_swap(bits) \
    static inline __attribute__((always_inline)) u ## bits atomic_swap_ ## bits(u ## bits *variable, u ## bits value) \
    { return __atomic_exchange_n(variable, value, __ATOMIC_SEQ_CST); }

mk_atomic_swap(8)
mk_atomic_swap(16)
mk_atomic_swap(32)
mk_atomic_swap(64)

static inline __attribute__((always_inline)) u8 compare_and_swap_64(u64 *p, u64 old, u64 new)
{
    return __sync_bool_compare_and_swap(p, old, new);
}

static inline __attribute__((always_inline)) u8 compare_and_swap_32(u32 *p, u32 old, u32 new)
{
    return __sync_bool_compare_and_swap(p, old, new);
}

static inline __attribute__((always_inline)) u8 compare_and_swap_8(u8 *p, u8 old, u8 new)
{
    return __sync_bool_compare_and_swap(p, old, new);
}

static inline __attribute__((always_inline)) void atomic_set_bit(u64 *target, u64 bit)
{
    asm volatile("lock btsq %1, %0": "+m"(*target): "r"(bit) : "memory");
}

static inline __attribute__((always_inline)) void atomic_clear_bit(u64 *target, u64 bit)
{
    asm volatile("lock btrq %1, %0": "+m"(*target):"r"(bit) : "memory");
}

static inline __attribute__((always_inline)) u8 atomic_test_and_set_bit(u64 *target, u64 bit)
{
    u8 oldbit;
    #ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm volatile("lock btsq %2, %0" : "+m"(*target), "=@ccc"(oldbit) : "r"(bit) : "memory");
    #else
    asm volatile("lock btsq %2, %0\nsetc %1" : "+m"(*target), "=m"(oldbit) : "r"(bit) : "memory");
    #endif
    return oldbit;
}

static inline __attribute__((always_inline)) u8 atomic_test_and_clear_bit(u64 *target, u64 bit)
{
    u8 oldbit;
    #ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm volatile("lock btrq %2, %0" : "+m"(*target), "=@ccc"(oldbit) : "r"(bit) : "memory");
    #else
    asm volatile("lock btrq %2, %0\nsetc %1" : "+m"(*target), "=m"(oldbit) : "r"(bit) : "memory");
    #endif
    return oldbit;
}

static inline __attribute__((always_inline)) void kern_pause(void)
{
    asm volatile("pause");
}

struct arch_vdso_dat {
    u8 platform_has_rdtscp;
};
