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

typedef u64 address;

#define NULL ((void *)0)

typedef void *status;
void allocate_status(char *format, ...);
