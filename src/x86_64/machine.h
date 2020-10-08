#ifdef BOOT
#include <def32.h>
#else
/* kernel or userland */
#include <def64.h>

#define KMEM_BASE   0xffff800000000000ull
#define USER_LIMIT  0x0000800000000000ull

#ifdef KERNEL
#define VA_TAG_BASE   KMEM_BASE
#define VA_TAG_OFFSET 39
#define VA_TAG_WIDTH  8
#else
#define VA_TAG_BASE   0
#define VA_TAG_OFFSET USER_VA_TAG_OFFSET
#define VA_TAG_WIDTH  USER_VA_TAG_WIDTH
#endif

static inline __attribute__((always_inline)) void *tag(void* v, u64 tval) {
    return pointer_from_u64(VA_TAG_BASE | (tval << VA_TAG_OFFSET) | u64_from_pointer(v));
}

static inline __attribute__((always_inline)) u16 tagof(void* v) {
    return (u64_from_pointer(v) >> VA_TAG_OFFSET) & ((1ull << VA_TAG_WIDTH) - 1);
}

#define valueof(__x) (__x)

typedef struct spinlock {
    word w;
} *spinlock;

typedef struct rw_spinlock {
    struct spinlock l;
    u64 readers;
} *rw_spinlock;
#endif

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

static inline __attribute__((always_inline)) void atomic_set_bit(u64 *target, u64 bit)
{
    asm volatile("lock btsq %1, %0": "+m"(*target): "r"(bit) : "memory");
}

static inline __attribute__((always_inline)) void atomic_clear_bit(u64 *target, u64 bit)
{
    asm volatile("lock btrq %1, %0": "+m"(*target):"r"(bit) : "memory");
}

static inline __attribute__((always_inline)) int atomic_test_and_set_bit(u64 *target, u64 bit)
{
    int oldbit;
    #ifdef __GCC_ASM_FLAG_OUTPUTS__
    asm volatile("lock btsq %2, %0" : "+m"(*target), "=@ccc"(oldbit) : "r"(bit) : "memory");
    #else
    asm volatile("lock btsq %2, %0\nsetc %1" : "+m"(*target), "=m"(oldbit) : "r"(bit) : "memory");
    #endif
    return oldbit;
}

static inline __attribute__((always_inline)) int atomic_test_and_clear_bit(u64 *target, u64 bit)
{
    int oldbit;
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

#if defined(KERNEL) || defined(BUILD_VDSO)
static inline u64
_rdtscp(void)
{
    u32 a, d;
    asm volatile("rdtscp" : "=a" (a), "=d" (d) :: "%rcx");
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
_rdtsc(void)
{
    u32 a, d;
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
rdtsc(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();
    return _rdtsc();
}

static inline u64
rdtsc_ordered(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();

    /* Now both AMD and Intel has lfence  */
    __asm __volatile("lfence" : : : "memory");
    return _rdtsc();
}

static inline u64
rdtsc_precise(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();

    asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx"); /* serialize execution */
    return _rdtsc();
}
#endif
