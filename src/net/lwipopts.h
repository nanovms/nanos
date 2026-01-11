/* guard against double include of header file */
#ifndef KMEM_BASE
#include <kernel.h>
#endif

#define NO_SYS 1
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define ARP_QUEUEING 1
//#define LWIP_DEBUG
#ifdef LWIP_DEBUG
#define LWIP_PLATFORM_DIAG(x) do {rprintf x;} while(0)
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

/* Must be a type on which atomic operations are supported by the CPU. */
#define LWIP_PBUF_REF_T u32_t

#define LWIP_CHKSUM_ALGORITHM   3

#define LWIP_WND_SCALE 1
#define TCP_MSS 1460            /* Assuming ethernet; may want to derive this */
#define TCP_WND 0x34000         /* For maximum throughput should be the same as TCP_SND_BUF */
#define TCP_SND_BUF 0x34000     /* Same as /proc/sys/net/core/wmem_default on Linux */
#define TCP_SNDLOWAT (0xFFFE - (4 * TCP_MSS))   /* Unused, but needed to pass lwIP sanity checks */
#define TCP_SND_QUEUELEN TCP_SNDQUEUELEN_OVERFLOW
#define TCP_OVERSIZE TCP_MSS
#define TCP_QUEUE_OOSEQ 1

#define TCP_RCV_SCALE 2         /* (0xFFFFU << TCP_RCV_SCALE) must be greater than TCP_WND */
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
#define LWIP_NETIF_EXT_STATUS_CALLBACK  1
#define LWIP_TIMERS 1
#define LWIP_TIMERS_CUSTOM 0
#define LWIP_DHCP_BOOTP_FILE 1
#define LWIP_DNS 1
#define LWIP_INCLUDED_POLARSSL_MD5  1

#define SO_REUSE 1
#define LWIP_IPV6   1
#define LWIP_IPV6_DHCP6 1
#define IPV6_FRAG_COPYHEADER    1

#define LWIP_STATS  0

#define LWIP_HOOK_IP4_INPUT net_ip_input_hook
#define LWIP_HOOK_IP6_INPUT net_ip_input_hook

typedef unsigned long u64_t;
typedef unsigned u32_t;
typedef int s32_t;
typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef short s16_t;
typedef signed char s8_t;
typedef u16_t uint16_t;
typedef void *sys_prot_t;
typedef struct spinlock sys_lock_t;
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

#define SYS_ARCH_LOCK_INIT  spin_lock_init
#define SYS_ARCH_LOCK       spin_lock
#define SYS_ARCH_UNLOCK     spin_unlock
#define SYS_ARCH_TRYLOCK    spin_try

#define SYS_ARCH_INC(var, val) __sync_fetch_and_add(&(var), val)
#define SYS_ARCH_DEC(var, val) __sync_fetch_and_add(&(var), -(val))

#define SYS_PAUSE   kern_pause

// some ifdef rot
#define API_MSG_M_DEF(m)                m
#define API_MSG_M_DEF_C(t, m)           t m

// and wtf
struct tcpip_api_call_data
{
};

#define SYS_LIGHTWEIGHT_PROT    0

typedef unsigned long long time; 

#define MEM_LIBC_MALLOC 1

#define lwip_htons(x)   PP_HTONS(x)
#define lwip_htonl(x)   PP_HTONL(x)

extern u32_t lwip_rand(void);
#define LWIP_RAND   lwip_rand

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

int lwip_atoi(sstring p);
void lwip_memcpy(void *a, const void *b, unsigned long len);
void lwip_memset(void *x, unsigned char v, unsigned long len);
int lwip_memcmp(const void *x, const void *y, unsigned long len);
int lwip_strncmp(const char *x, const char *y, unsigned long len);

#define memcpy(__a, __b, __c) lwip_memcpy(__a, __b, __c)
#define memcmp(__a, __b, __c) lwip_memcmp(__a, __b, __c)
#define memset(__a, __b, __c) lwip_memset((void *)(__a), __b, __c)
#define memmove(__a, __b, __c) lwip_memcpy(__a, __b, __c)
#define strncmp(__a, __b, __c) lwip_strncmp(__a, __b, __c)
#define strcmp(__a, __b) runtime_strcmp(__a, __b)
#define atoi(__a) lwip_atoi(__a)

static inline void *calloc(size_t n, size_t s)
{
    void *x =  lwip_allocate(n*s);
    lwip_memset(x, 0, n*s);
    return x;
}

struct pbuf;
struct netif;

static inline int net_ip_input_hook(struct pbuf *pbuf, struct netif *input_netif)
{
    extern int (*net_ip_input_filter)(struct pbuf *, struct netif *);
    if (net_ip_input_filter && !net_ip_input_filter(pbuf, input_netif))
        return 1;
    return 0;
}

/*
 * DHCP Option 121 (Classless Static Routes) support.
 *
 * The nanos lwIP modification passes ip_data as a parameter rather than
 * using a global. However, dhcp_parse_reply() calls the option hook using
 * ip_current_netif() which expects a global. We work around this by:
 * 1. Defining a global that stores the current netif during DHCP recv
 * 2. Providing ip_current_netif() macro to access it
 * 3. Implementing the hook to use this netif
 *
 * The global is set by the UDP recv callback wrapper before calling dhcp_recv.
 */
extern struct netif *nanos_dhcp_current_netif;

static inline struct netif *ip_current_netif(void)
{
    return nanos_dhcp_current_netif;
}

struct dhcp;
struct dhcp_msg;
extern void nanos_dhcp_parse_option_hook(struct netif *netif, struct dhcp *dhcp,
                                          u8_t state, struct dhcp_msg *msg,
                                          u8_t msg_type, u8_t option, u8_t len,
                                          struct pbuf *p, u16_t offset);
#define LWIP_HOOK_DHCP_PARSE_OPTION(netif, dhcp, state, msg, msg_type, option, len, pbuf, offset) \
    nanos_dhcp_parse_option_hook(netif, dhcp, state, msg, msg_type, option, len, pbuf, offset)

/*
 * Static route lookup hook for DHCP Option 121 routes.
 * Called by lwIP's ip4_route() to check static routes before the default route.
 */
struct ip4_addr;
extern struct netif *ip4_static_route(const struct ip4_addr *src, const struct ip4_addr *dest);
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest) ip4_static_route(src, dest)
