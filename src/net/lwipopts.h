#define NO_SYS 1
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define ARP_QUEUEING 1
//#define LWIP_DEBUG
#ifdef LWIP_DEBUG
#define LWIP_PLATFORM_DIAG(x) do {lwip_debug x;} while(0)
#define LWIP_DBG_MIN_LEVEL		LWIP_DBG_LEVEL_ALL
#define ETHARP_DEBUG                    LWIP_DBG_ON
#define NETIF_DEBUG                     LWIP_DBG_ON
#define PBUF_DEBUG                      LWIP_DBG_ON
#define API_LIB_DEBUG                   LWIP_DBG_ON
#define API_MSG_DEBUG                   LWIP_DBG_ON
#define SOCKETS_DEBUG                   LWIP_DBG_ON
//#define ICMP_DEBUG                      LWIP_DBG_ON
//#define IGMP_DEBUG                      LWIP_DBG_ON
//#define INET_DEBUG                      LWIP_DBG_ON
#define IP_DEBUG                        LWIP_DBG_ON
//#define IP_REASS_DEBUG                  LWIP_DBG_ON
//#define RAW_DEBUG                       LWIP_DBG_ON
//#define MEM_DEBUG                       LWIP_DBG_ON
//#define MEMP_DEBUG                      LWIP_DBG_ON
#define SYS_DEBUG                       LWIP_DBG_ON
//#define TIMERS_DEBUG                    LWIP_DBG_ON
#define TCP_DEBUG                       LWIP_DBG_ON
#define TCP_INPUT_DEBUG                 LWIP_DBG_ON
#define TCP_FR_DEBUG                    LWIP_DBG_ON
#define TCP_RTO_DEBUG                   LWIP_DBG_ON
#define TCP_CWND_DEBUG                  LWIP_DBG_ON
#define TCP_WND_DEBUG                   LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG                LWIP_DBG_ON
#define TCP_RST_DEBUG                   LWIP_DBG_ON
#define TCP_QLEN_DEBUG                  LWIP_DBG_ON
#define UDP_DEBUG                       LWIP_DBG_ON
#define TCPIP_DEBUG                     LWIP_DBG_ON
//#define SLIP_DEBUG                      LWIP_DBG_ON
//#define DHCP_DEBUG                      LWIP_DBG_ON
//#define AUTOIP_DEBUG                    LWIP_DBG_ON
//#define DNS_DEBUG                       LWIP_DBG_ON
//#define IP6_DEBUG                       LWIP_DBG_ON
#else
#define LWIP_PLATFORM_DIAG
#endif /* LWIP_DEBUG */
#define LWIP_PLATFORM_ASSERT(x)
#define LWIP_NO_STDDEF_H 1
#define LWIP_NO_STDINT_H 1
#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_LIMITS_H 1
#define LWIP_NO_CTYPE_H 1

#define LWIP_WND_SCALE 1
#define TCP_MSS 1460            /* Assuming ethernet; may want to derive this */
#define TCP_WND 65535
#define TCP_SND_BUF 65535
#define TCP_SND_QUEUELEN TCP_SNDQUEUELEN_OVERFLOW
#define TCP_OVERSIZE TCP_MSS
#define TCP_QUEUE_OOSEQ 1

#define TCP_RCV_SCALE 0         /* XXX check */
#define TCP_LISTEN_BACKLOG 1
#define LWIP_DHCP 1
// would prefer to set this dynamically...also,
// seems better to allow some progress to be made
// and then cede if there is a collison? or at least
// some other policy
#define DHCP_DOES_ARP_CHECK 0
#define LWIP_NETIF_LOOPBACK 1
#define LWIP_NETIF_HOSTNAME 1
#define MEMP_MEM_MALLOC 1
typedef unsigned long size_t;
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_TIMERS 1
#define LWIP_TIMERS_CUSTOM 1
#define LWIP_DHCP_BOOTP_FILE 1

#define LWIP_IPV6   1

typedef unsigned long u64_t;
typedef unsigned u32_t;
typedef int s32_t;
typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef short s16_t;
typedef signed char s8_t;
typedef u16_t uint16_t;
typedef void *sys_prot_t;
typedef u64_t ptrdiff_t;
typedef unsigned long mem_ptr_t;

// format specifiers
#define X8_F "2x"		/* not actually hex */
#define U16_F "d"
#define S16_F "d"
#define X16_F "d"
#define U32_F "d"
#define S32_F "d"
#define X32_F "8x"
#define SZT_F "d"

// some ifdef rot
#define API_MSG_M_DEF(m)                m
#define API_MSG_M_DEF_C(t, m)           t m

// and wtf
struct tcpip_api_call_data
{
};

static inline sys_prot_t sys_arch_protect(void)
{
    return 0;
}

static inline void sys_arch_unprotect(sys_prot_t x)
{
}

typedef unsigned long long time; 
extern void lwip_debug(char * format, ...);

#define MEM_LIBC_MALLOC 1

extern void net_debug(char *format, ...);
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

int lwip_atoi(const char *p);
void lwip_memcpy(void *a, const void *b, unsigned long len);
int lwip_strlen(char *a);
void lwip_memset(void *x, unsigned char v, unsigned long len);
int lwip_memcmp(const void *x, const void *y, unsigned long len);
int lwip_strncmp(const char *x, const char *y, unsigned long len);

#define memcpy(__a, __b, __c) lwip_memcpy(__a, __b, __c)
#define memcmp(__a, __b, __c) lwip_memcmp(__a, __b, __c)
#define memset(__a, __b, __c) lwip_memset((void *)(__a), __b, __c)
#define memmove(__a, __b, __c) lwip_memcpy(__a, __b, __c)
#define strlen(__a) lwip_strlen((void *)__a)
#define strncmp(__a, __b, __c) lwip_strncmp(__a, __b, __c)
#define atoi(__a) lwip_atoi(__a)

static inline void *calloc(size_t n, size_t s)
{
    void *x =  lwip_allocate(n*s);
    lwip_memset(x, 0, n*s);
    return x;
}

