#define NO_SYS 2
#define LWIP_PLATFORM_DIAG(x)
#define LWIP_PLATFORM_ASSERT(x)
#define LWIP_NO_STDDEF_H 1
#define LWIP_NO_STDINT_H 1
#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_LIMITS_H 1
#define LWIP_NO_CTYPE_H 1
#define LWIP_DHCP 1
#define MEMP_MEM_MALLOC 1
typedef unsigned long size_t;

typedef unsigned long u64_t;
typedef unsigned u32_t;
typedef int s32_t;
typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef short s16_t;
typedef char s8_t;
typedef u16_t uint16_t;

// otherwise all sorts of terrible things about the definition of NULL
#include <string.h>

typedef void *sys_prot_t;

typedef u64_t ptrdiff_t;

typedef unsigned long mem_ptr_t;

// some ifdef rot
#define API_MSG_M_DEF(m)                m
#define API_MSG_M_DEF_C(t, m)           t m

// and wtf
struct tcpip_api_call_data
{
};

static inline sys_prot_t sys_arch_protect(void)
{
}

static inline void sys_arch_unprotect(sys_prot_t x)
{
}

extern void console(char *);

static inline u32_t sys_now(void)
{
    static int t = 0;
    console("now\n");
    return t++;
}

#define MEM_LIBC_MALLOC 1

extern void *gallocate();

static inline void *lwip_malloc(size_t b)
{
    return gallocate(b);
}

#define mem_clib_malloc lwip_malloc

static inline void free(void *x)
{
}

//static inline void *calloc(size_t b)
//{
//    void *x =     gallocate(b);
//    memset(x, 0, b);
//}
