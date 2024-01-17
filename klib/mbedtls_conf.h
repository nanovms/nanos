#ifndef _RUNTIME_H_
#include <runtime.h>
#endif
#include <mktime.h>

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

#define MBEDTLS_PLATFORM_CALLOC_MACRO       mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO         mbedtls_free
#define MBEDTLS_PLATFORM_TIME_MACRO         rtime
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO    long
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO     rsnprintf

void *mbedtls_calloc(size_t n, size_t s);
void mbedtls_free(void *ptr);

#ifndef memset
#define memset(block, c, size)  runtime_memset((void *)(block), c, size)
#endif
#ifndef memcpy
#define memcpy  runtime_memcpy
#endif
#ifndef memmove
#define memmove runtime_memcpy
#endif
#ifndef memcmp
#define memcmp  runtime_memcmp
#endif
#ifndef strcmp
#define strcmp  runtime_strcmp
#endif
#ifndef strchr
#define strchr  runtime_strchr
#endif
#ifndef strstr
#define strstr  runtime_strstr
#endif
