
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
#define LWIP_NETIF_STATUS_CALLBACK 1
// ehh
#define LWIP_DHCP_BOOTP_FILE 1
typedef unsigned long u64_t;
typedef unsigned u32_t;
typedef int s32_t;
typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef short s16_t;
typedef char s8_t;
typedef u16_t uint16_t;

// otherwise all sorts of terrible things about the definition of NULL
// #include <string.h>

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
    return t+=200;
}

#define MEM_LIBC_MALLOC 1

extern void *lwip_allocate(unsigned long long size);
extern void lwip_deallocate(void *z);

static inline void *lwip_malloc(size_t b)
{
    return lwip_allocate(b);
}

#define mem_clib_malloc lwip_allocate
#define mem_clib_free lwip_free

static inline void lwip_free(void *x)
{
    lwip_deallocate(x);
}


// sad duplication
static inline void lwip_memcpy(void *a, const void *b, unsigned long len)
{
    for (int i = 0; i < len; i++) ((unsigned char *)a)[i] = ((unsigned char *)b)[i];
}

static inline int lwip_strlen(char *a)
{
    int i = 0;
    for (char *z = a; *a; a++, i++);
    return i;
}

static inline void lwip_memset(void *x, unsigned char v, unsigned long len)
{
    for (int i = 0; i < len; i++) ((unsigned char *)x)[i] = v;
}

// the #define isn't reaching ethernet.o
static inline int lwip_memcmp(const void *x, const void *y, unsigned long len)
{
    for (int i = 0; i < len; i++) {
        if (x < y) return -1;
        if (x > y) return 1;        
    }
    return 0;
}


static inline int lwip_strncmp(const char *x, const char *y, unsigned long len)
{
    for (int i = 0; i < len; i++) {
        if ((*x) != (*y)) return -1;
        if ((!*x) || (!*y)) return -1;
    }
    return 0;
}

#define memcpy(__a, __b, __c) lwip_memcpy(__a, __b, __c)
#define memcmp(__a, __b, __c) lwip_memcmp(__a, __b, __c)
#define memset(__a, __b, __c) lwip_memset((void *)(__a), __b, __c)
#define strlen(__a) lwip_strlen((void *)__a)
#define strncmp(__a, __b, __c) lwip_strncmp(__a, __b, __c)

static inline void *calloc(size_t n, size_t s)
{
    void *x =  lwip_allocate(n*s);
    lwip_memset(x, 0, n*s);
}
