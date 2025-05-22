#define physical_from_virtual(__x) u64_from_pointer(__x)

typedef struct tagged_allocator {
    struct heap h;
    u8 tag;
    heap parent;
} *tagged_allocator;

static inline u64 tagged_allocate(heap h, bytes length)
{
    tagged_allocator ta = (void *)h;
    u64 base = allocate_u64(ta->parent, length + 8);    /* 8 bytes to preserve 64-bit alignment */
    if (base == INVALID_PHYSICAL)
        return base;
    *(u8 *)pointer_from_u64(base + 7) = ta->tag;
    return base + 8;
}

static inline void tagged_deallocate(heap h, u64 a, bytes length)
{
    tagged_allocator ta = (void *)h;
    deallocate_u64(ta->parent, a - 8, length + 8);
}

static inline heap allocate_tagged_region(heap h, u64 tag)
{
    tagged_allocator ta = allocate(h, sizeof(struct tagged_allocator));
    ta->h.alloc = tagged_allocate;
    ta->h.dealloc = tagged_deallocate;
    ta->tag = tag;
    ta->parent = h;
    return (heap)ta;
}

static inline __attribute__((always_inline)) u8 is_immediate(value v)
{
    return ((word)v & 1) != 0;
}

static inline __attribute__((always_inline)) u8 is_immediate_integer(value v)
{
    return ((word)v & 0x3) == 1;
}

static inline value_tag tagof(value v)
{
    if (is_immediate_integer(v))
        return tag_integer;
    return *((u8 *)v-1);
}

extern heap boot_buffer_heap;
void *load_kernel_elf(buffer b, heap bss_heap);
