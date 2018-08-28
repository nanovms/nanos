typedef struct bitmap {
    u64 maxbits;
    u64 mapbits;
    heap h;
    buffer alloc_map;
} *bitmap;

u64 bitmap_alloc(bitmap b, int order);
boolean bitmap_dealloc(bitmap b, u64 bit, u64 order);
bitmap allocate_bitmap(heap h, u64 length);
void deallocate_bitmap(bitmap b);
