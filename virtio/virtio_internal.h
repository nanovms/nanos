#include <runtime.h>

// closures
typedef struct handler {
    void (*f)(void *);
    void *a;
} *handler;
    
typedef u64 uint64_t;
typedef u32 uint32_t;
typedef u16 uint16_t;
typedef u8 uint8_t;

typedef u64 physical;
typedef u64 virtual;

#define PAGESIZE 4096

#define ETHER_ADDR_LEN 6

#define NULL ((void *)0)

typedef void *status;
status allocate_status(char *format, ...);
static inline status status_nomem() {return (void *)1;}


static inline boolean is_ok(status s)
{
    return s == NULL;
}

#define NULL ((void *)0)



// probably important
static inline void write_barrier()
{
}
static inline void read_barrier()
{
}
static inline void memory_barrier()
{
}

struct virtqueue;

#define STATUS_OK NULL

typedef struct buffer {
    u32 start, end, fill;
    void *contents;
    struct buffer *next;
} *buffer;

static inline u64 buffer_length(buffer b)
{
    return b->end - b->start;
}

typedef u64 address;
status virtqueue_alloc(void *dev,
                       char *name, 
                       uint16_t queue,
                       uint16_t size,
                       int align,
                       address highaddr,
                       handler interrupt,
                       int maxindirsz, 
                       struct virtqueue **vqp);

#include <virtqueue.h>
#include <virtio_ring.h>
#include <virtio_config.h>
#include <virtio_pci.h>

extern heap general;
extern void *memset(void *a, int val, bytes length);

static inline physical vtophys(void *v)
{
    return (u64)v;
}

#define cprintf(...)
#define apply(...)

