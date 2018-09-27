/* bitmap allocator

   All allocations are power-of-2 sized and aligned to size.
   The bitmap length may be arbitrarily sized.
   The bitmap buffer is allocated in ALLOC_EXTEND_BITS / 8 byte increments as needed.
*/

#include <runtime.h>

static inline u64 * pointer_from_bit(u64 * base, u64 bit)
{
    return base + (bit >> 6);
}

static boolean for_range_in_map(u64 * base, u64 start, u64 order, boolean set, boolean val)
{
    u64 nbits = 1 << order;
    u64 wlen = ((nbits - 1) >> 6) + 1;
    u64 mask = nbits >= 64 ? -1 : (((u64)1 << nbits) - 1) << (64 - nbits - start);
    u64 * w = pointer_from_bit(base, start);
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

#define check_skip(a, z, n, b) if(n >= a && z >= n) { z -= n; b += n; }

u64 bitmap_alloc(bitmap b, int order)
{
    u64 bit = 0;
    u64 alloc_bits = 1 << order;
    u64 * mapbase = bitmap_base(b);

    do {
	/* Check if we need to expand the map */
	if (bitmap_extend(b, bit + alloc_bits))
	    mapbase = bitmap_base(b);

	/* Avoid checking bitmap word multiple times for small allocations */
	if (order < 6 && (bit & 63) == 0) {
	    u64 inv = ~*pointer_from_bit(mapbase, bit);
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

	if (bit + alloc_bits > b->maxbits)
	    break;

	if (for_range_in_map(mapbase, bit, order, false, false)) {
	    for_range_in_map(mapbase, bit, order, true, true);
	    return bit;
	}

	/* XXX should skip trailing / intermediate set bits too */

	bit += alloc_bits;
    } while(bit < b->maxbits);

    return INVALID_PHYSICAL;
}

boolean bitmap_dealloc(bitmap b, u64 bit, u64 order)
{
    u64 nbits = 1 << order;
    u64 * mapbase = bitmap_base(b);
    assert(mapbase);

    /* XXX maybe error code instead of msg_err... */
    if (bit & (nbits - 1)) {
	msg_err("bitmap %p, bit %d is not aligned to order %d\n",
		b, bit, order);
	return false;
    }

    if (bit + nbits > b->maxbits) {
	msg_err("bitmap %p, bit %d, order %d: exceeds bit length %d\n",
		b, bit, order, b->maxbits);
	return false;
    }

    if (!for_range_in_map(mapbase, bit, order, false, true)) {
	msg_err("bitmap %p, bit %d, order %d: not allocated in map; leaking\n",
		b, bit, order);
	return false;
    }

    for_range_in_map(mapbase, bit, order, true, false);
    return true;
}

bitmap allocate_bitmap(heap h, u64 length)
{
    assert(length > 0);
    bitmap b = allocate(h, sizeof(struct bitmap));
    b->h = h;
    if (length == infinity)
	length = -1ull << 6; /* don't pad to 0 */
    b->maxbits = length;
    b->mapbits = MIN(ALLOC_EXTEND_BITS, pad(b->maxbits, 64));
    u64 mapbytes = b->mapbits >> 3;
    b->alloc_map = allocate_buffer(h, mapbytes);
    if (b->alloc_map == INVALID_ADDRESS) {
	return INVALID_ADDRESS;
    }
    zero(bitmap_base(b), mapbytes);
    buffer_produce(b->alloc_map, mapbytes);
    return b;
}

void deallocate_bitmap(bitmap b)
{
    if (b->alloc_map)
	deallocate_buffer(b->alloc_map);
    deallocate(b->h, b, sizeof(struct bitmap));
}
