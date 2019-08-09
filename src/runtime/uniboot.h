#pragma once

#include <predef.h>

#ifdef BOOT
#include <def32.h>
/* Keep this reasonable so we don't blow the stage2 working heap. */
#define TABLE_MAX_BUCKETS       1024
#else

#include <def64.h>
#define user_va_tag_offset 44
#ifdef STAGE3
#define va_tag_offset 40        /* 1TB */
#else
#define va_tag_offset user_va_tag_offset
#endif

/* maximum buckets that can fit within a PAGESIZE_2M mcache */
#define TABLE_MAX_BUCKETS       131072

static inline void* tag(void* v, u64 tval) {
  return pointer_from_u64((tval << va_tag_offset) | u64_from_pointer(v));
}

static inline u16 tagof(void* v) {
  return (u64_from_pointer(v) >> va_tag_offset);
}

#define valueof(__x) (__x)

#endif /* BOOT */

#include <x86.h>
