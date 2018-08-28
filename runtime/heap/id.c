#include <runtime.h>

typedef struct id_heap {
    struct heap h;
    u64 base;
    u64 maxbits;
    u64 mapbits;
    buffer alloc_map;
} *id_heap;

/* XXX keep allocs small for now; rolling heap allocations more than a
   page are b0rked */
#define ALLOC_EXTEND_BITS	(1 << 12)

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
    int alloc_bits = 1 << order;
    u64 * mapbase = buffer_ref(i->alloc_map, 0);

    do {
	/* Check if we need to expand the map */
	if (bit + alloc_bits >= i->mapbits) {
	    bytes old = i->mapbits >> 3;
	    i->mapbits = pad(bit + alloc_bits + 1, ALLOC_EXTEND_BITS);
	    bytes new = i->mapbits >> 3;
	    extend_total(i->alloc_map, new);
	    mapbase = buffer_ref(i->alloc_map, 0);
	}

	/* Avoid checking bitmap word multiple times for small allocations */
	if (order < 6 && (bit & 63) == 0) {
	    u64 inv = ~word_at_bit(mapbase, bit);
	    if (inv == 0) {
		bit += 64;
		continue;
	    }

	    /* Advance over allocated bits to order boundary;
	       room for improvement here... */
	    u64 nlz = 63 - msb(inv);
	    check_skip(alloc_bits, nlz, 32, bit);
	    check_skip(alloc_bits, nlz, 16, bit);
	    check_skip(alloc_bits, nlz, 8, bit);
	    check_skip(alloc_bits, nlz, 4, bit);
	    check_skip(alloc_bits, nlz, 2, bit);
	    check_skip(alloc_bits, nlz, 1, bit);
	    check_skip(alloc_bits, nlz, 0, bit);
	}

	if (bit + alloc_bits > i->maxbits)
	    break;

	if (for_range_in_map(i, bit, order, false, false)) {
	    for_range_in_map(i, bit, order, true, true);
	    u64 offset = (u64)bit << page_order(i);
#ifdef ID_HEAP_DEBUG
	    msg_debug("heap %p, size %d: got offset (%d << %d = %P)\t>%P\n",
		      h, alloc_bits, bit, page_order(i), offset, i->base + offset);
#endif
	    return i->base + offset;
	}

	bit += alloc_bits;
    } while(bit < i->maxbits);

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

    if (bit + nbits > i->maxbits) {
	msg_err("heap %p, offset %P, count %d: extends beyond length %P; leaking\n",
		h, a - i->base, count, i->maxbits << page_order(i));
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
    i->base = base;
    i->maxbits = length >> page_order(i);
    i->mapbits = MIN(ALLOC_EXTEND_BITS, pad(i->maxbits, 64));

    u64 mapbytes = i->mapbits >> 3;
    i->alloc_map = allocate_buffer(h, mapbytes);
    if (i->alloc_map == INVALID_ADDRESS) {
	console("create_id_heap: failed to allocate map buffer of ");
	print_u64(mapbytes);
	console(" bytes!\n");
	return INVALID_ADDRESS;
    }
    zero(buffer_ref(i->alloc_map, 0), mapbytes);
    buffer_produce(i->alloc_map, mapbytes);
    return((heap)i);
}
