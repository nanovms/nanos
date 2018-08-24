#include <def64.h>

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

#define valueof(__x) (__x)

