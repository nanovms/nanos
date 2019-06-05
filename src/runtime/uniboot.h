#pragma once

#include <predef.h>

#ifdef BOOT
#include <def32.h>
#else

#include <def64.h>
#define user_va_tag_offset 44
#ifdef STAGE3
// each type gets 1T
// this is to avoid colliding with the kernel when running on stage3.
#define va_tag_offset 40
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

#endif // BOOT

#include <x86.h>
