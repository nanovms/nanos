#pragma once

#include <predef.h>
#ifdef BOOT
#include <def32.h>
#elif defined(STAGE3) || defined(UNIX_PROCESS)
#include <def64.h>
// each type gets 1T
// this is to avoid colliding with the kernel when running on stage3.
#ifndef STAGE3
typedef int descriptor;
heap init_process_runtime();
heap allocate_mmapheap(heap meta, bytes size);
#define va_tag_offset 44
#else
#define va_tag_offset 40
#endif

static inline void* tag(void* v, u64 tval) {
  return pointer_from_u64((tval << va_tag_offset) | u64_from_pointer(v));
}

static inline u16 tagof(void* v) {
  return (u64_from_pointer(v) >> va_tag_offset);
}

#define valueof(__x) (__x)
#endif
