
typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

#define pointer_from_u64(__a) ((void *)(__a))
#define u64_from_pointer(__a) ((u64)(__a))
// a super sad hack to allow us to write to the bss in elf.c as
// phy instead of virt
#define vpzero(__v, __p, __y) zero(pointer_from_u64(__v), __y)

// each type gets 1T
#define va_tag_offset 40

static inline void *tag(void *v, u64 tval)
{
    return pointer_from_u64((tval<<va_tag_offset)|u64_from_pointer(v));
}

static inline u16 tagof(void *v)
{
    return (u64_from_pointer(v)>>va_tag_offset);
}

static inline void *valueof(void *v)
{
    return v;
}
