#include <runtime.h>

typedef struct id_heap {
    struct heap h;
    u64 length;
    u64 base;
    buffer alloc_map;
} *id_heap;

static boolean for_range_in_map(id_heap i, u64 start, u64 order, boolean set, boolean val)
{
    u64 nbits = 1 << order;
    u64 wlen = ((nbits - 1) >> 6) + 1;
    u64 mask = nbits >= 64 ? -1 : (((u64)1 << nbits) - 1) << (64 - nbits - start);
    u64 * w = (u64*)(buffer_ref(i->alloc_map, 0)) + (start >> 6);
    u64 * wend = w + wlen;
    for (; w < wend; w++) {
	if (set) {
	    *w = val ? *w | mask : *w & ~mask;
	} else {
	    u64 masked = mask & *w;
	    if ((val ? masked : (masked ^ mask)) != mask)
		return false;
	}
    }
    return true;
}

#define page_order(i) msb(i->h.pagesize)

static inline int find_order(id_heap i, bytes alloc_size)
{
    int order = pad(alloc_size, i->h.pagesize) >> page_order(i);
    return order > 1 ? msb(order - 1) + 1 : 0;	/* round up to next power of 2 */
}

static inline u64 word_at_bit(u64 * base, int bit)
{
    return *(base + (bit >> 6));
}

#define check_skip(a, z, n, b) if(n >= a && z >= n) { z -= n; b += n; }

static u64 id_alloc(heap h, bytes count)
{
    id_heap i = (id_heap)h;

    if (count == 0)
	return INVALID_PHYSICAL;

    int order = find_order(i, count);
    int bit = 0;
    int total_bits = i->length >> page_order(i);
    int alloc_bits = 1 << order;
    u64 * mapbase = buffer_ref(i->alloc_map, 0);

    do {
	/* Avoid checking bitmap word multiple times for small allocations */
	if (order < 6 && (bit & 63) == 0) {
	    u64 inv = ~word_at_bit(mapbase, bit);
	    if (inv == 0) {
		bit += 64;
		continue;
	    }

	    /* Advance over allocated bits to order boundary */
	    u64 nlz = 63 - msb(inv);
	    check_skip(alloc_bits, nlz, 32, bit);
	    check_skip(alloc_bits, nlz, 16, bit);
	    check_skip(alloc_bits, nlz, 8, bit);
	    check_skip(alloc_bits, nlz, 4, bit);
	    check_skip(alloc_bits, nlz, 2, bit);
	    check_skip(alloc_bits, nlz, 1, bit);
	    check_skip(alloc_bits, nlz, 0, bit);
	}

	if (for_range_in_map(i, bit, order, false, false)) {
	    for_range_in_map(i, bit, order, true, true);
	    u64 offset = bit << page_order(i);
#ifdef ID_HEAP_DEBUG
	    msg_debug("heap %p, size %d: got offset (%d << %d = %P)\t>%P\n",
		      h, 1 << order, bit, page_order(i), offset, i->base + offset);
#endif
	    return i->base + offset;
	}

	bit += alloc_bits;
    } while(bit < total_bits);

    return INVALID_PHYSICAL;
}

static void id_dealloc(heap h, u64 a, bytes count)
{
    id_heap i = (id_heap)h;

    if (count == 0)
	return;

    int order = find_order(i, count);
    int nbits = 1 << order;

    if (a & (nbits - 1)) {
	msg_err("heap %p, address %P is unaligned; leaking\n", h, a);
	return;
    }

    int bit = (a - i->base) >> page_order(i);

    if (bit + nbits > (i->length >> page_order(i))) {
	msg_err("heap %p, offset %P, count %d: extends beyond length %P; leaking\n",
		h, a - i->base, count, i->length);
	return;
    }

    if (!for_range_in_map(i, bit, order, false, true)) {
	msg_err("heap %p, address %P, count %d: not allocated in map; leaking\n",
		h, a, count);
	return;
    }

    for_range_in_map(i, bit, order, true, false);
}

static void id_destroy(heap h)
{
    id_heap i = (id_heap)h;
    if (i->alloc_map)
	deallocate_buffer(i->alloc_map);
}

heap create_id_heap(heap h, u64 base, u64 length, u64 pagesize)
{
    /* assert that pagesize is power of 2 */
    assert((pagesize & (pagesize-1)) == 0);

    /* assert that length is a multiple of pagesize */
    assert((length & (pagesize-1)) == 0);

    id_heap i = allocate(h, sizeof(struct id_heap));
    i->h.alloc = id_alloc;
    i->h.dealloc = id_dealloc;
    i->h.pagesize = pagesize;
    i->h.destroy = id_destroy;
    i->length = length;
    i->base = base;

    u64 mapbits = (length + 63) & ~63;
    u64 mapbytes = mapbits >> 3;
    i->alloc_map = allocate_buffer(h, mapbytes);
    zero(buffer_ref(i->alloc_map, 0), mapbytes);
    return((heap)i);
}
