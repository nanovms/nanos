#ifndef _RUNTIME_H_
#include <runtime.h>
#endif

#define NULL    ((void *)0)

#define CHAR_BIT    8

#define INT_MAX     0x7fffffff
#define UINT_MAX    0xffffffff
#define SIZE_MAX    0x7fffffffffffffffll

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;

typedef unsigned long size_t;
typedef unsigned long uintptr_t;

struct tm {
    int tm_year;
    uint8_t tm_mon;
    uint8_t tm_mday;
    uint8_t tm_hour;
    uint8_t tm_min;
    uint8_t tm_sec;
};

extern struct kern_funcs {
    void (*memset)(void *a, unsigned char b, unsigned long len);
    void (*memcopy)(void *a, const void *b, unsigned long len);
    int (*memcmp)(const void *a, const void *b, unsigned long len);
    int (*strcmp_f)(const char *string1, const char *string2);
    char *(*strstr_f)(const char *haystack, const char *needle);
    long (*time_f)(long *result);
    int (*rsnprintf)(char *str, u64 size, const char *fmt, ...);
} kern_funcs;

#define MBEDTLS_PLATFORM_CALLOC_MACRO       mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO         mbedtls_free
#define MBEDTLS_PLATFORM_TIME_MACRO         kern_funcs.time_f
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO    long
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO     kern_funcs.rsnprintf

void *mbedtls_calloc(size_t n, size_t s);
void mbedtls_free(void *ptr);

#ifndef memset
#define memset  kern_funcs.memset
#endif
#ifndef memcpy
#define memcpy  kern_funcs.memcopy
#endif
#ifndef memmove
#define memmove kern_funcs.memcopy
#endif
#ifndef memcmp
#define memcmp  kern_funcs.memcmp
#endif
#ifndef strlen
#define strlen  runtime_strlen
#endif
#ifndef strcmp
#define strcmp  kern_funcs.strcmp_f
#endif
#ifndef strstr
#define strstr  kern_funcs.strstr_f
#endif
