// XXX
static inline void out8(u32 port, u8 data)
{
//    __asm __volatile("outb %0, %w1" : : "a" (data), "Nd" (port));
}

static inline void out16(u32 port, u16 data)
{
//    __asm __volatile("outw %0, %w1" : : "a" (data), "Nd" (port));
}

static inline void out32(u32 port, u32 data)
{
//    __asm __volatile("outl %0, %w1" : : "a" (data), "Nd" (port));
}

static inline void outs32(u32 port, const void *addr, u32 count)
{
        /* __asm __volatile("cld; rep; outsl" */
        /*                  : "+S" (addr), "+c" (count) */
        /*                  : "d" (port)); */
}

static inline u8 in8(u32 port)
{
    /* unsigned char ret; */
    /* asm volatile ("inb %%dx,%%al":"=a" (ret):"d" (port)); */
    /* return ret; */
    return 0;
}

static inline u16 in16(u32 port)
{
    /* u16 data; */

    /* __asm __volatile("inw %w1, %0" : "=a" (data) : "Nd" (port)); */
    /* return (data); */
    return 0;
}

static inline u32 in32(u32 port)
{
    /* u32  data; */
    /* __asm __volatile("inl %w1, %0" : "=a" (data) : "Nd" (port)); */
    /* return (data); */
    return 0;
}

static inline void ins32(u32 port, void *addr, u32 count)
{
        /* __asm __volatile("cld; rep; insl" */
        /*                  : "+D" (addr), "+c" (count) */
        /*                  : "d" (port) */
        /*                  : "memory"); */
}

