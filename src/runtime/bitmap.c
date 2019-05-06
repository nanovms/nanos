/* bitmap allocator

   Allocations are aligned to next power-of-2 equal or greater than
   allocation size. This allows a simpler and faster allocation
   algorithm, and also has the side-effect of allowing mixed page
   sizes (e.g. 4K + 2M) within the same space.

   The bitmap length may be arbitrarily sized. The bitmap buffer is
   allocated in ALLOC_EXTEND_BITS / 8 byte increments as needed.
*/

#include <runtime.h>

static inline u64 * pointer_from_bit(u64 * base, u64 bit)
{
    return base + (bit >> 6);
}

static boolean for_range_in_map(u64 * base, u64 start, u64 nbits, boolean set, boolean val)
{
    u64 wlen = ((nbits - 1) >> 6) + 1;
    u64 mask = nbits >= 64 ? -1 : ((1ull << nbits) - 1) << start;
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

/* Requesting beyond the end of maxbits isn't an error; the caller may
   use it to avoid an additional range check.

   While bitmap_alloc() serves power-of-2 sized and aligned
   allocations, our reserve does not require such alignment. The two
   should co-exist without issue. */
boolean bitmap_reserve(bitmap b, u64 start, u64 nbits)
{
    /* check both start and end in case of overflow / corrupt args */
    if (start >= b->maxbits || start + nbits > b->maxbits)
        return false;

    bitmap_extend(b, start + nbits - 1);
    u64 * mapbase = bitmap_base(b);
    return (for_range_in_map(mapbase, start, nbits, false, false) &&
            for_range_in_map(mapbase, start, nbits, true, true));
}

static u64 bitmap_alloc_internal(bitmap b, u64 nbits, u64 startbit, u64 endbit)
{
    u64 bit = startbit;
    int order = find_order(nbits);
    u64 stride = U64_FROM_BIT(order);
    u64 * mapbase = bitmap_base(b);

    assert((startbit & MASK(order)) == 0);

    if (nbits >= 64) {
        /* multi-word */
        while (bit + nbits <= endbit) {
            if (bitmap_extend(b, bit + nbits))
                mapbase = bitmap_base(b);

            if (for_range_in_map(mapbase, bit, nbits, false, false)) {
                for_range_in_map(mapbase, bit, nbits, true, true);
                return bit;
            }

            bit += stride;
        }
    } else {
        /* allocations up to a word's worth of bits */
        for (; bit + nbits <= endbit; bit += 64) {
            if (bitmap_extend(b, bit + 64))
                mapbase = bitmap_base(b);

            int shift = 0;
            u64 mask = MASK(nbits);
            u64 bw = *pointer_from_bit(mapbase, bit);

            if (bw == -1ull)    /* skip full words */
                continue;

            do {
                if ((bw & mask) == 0) {
                    assert(for_range_in_map(mapbase, bit + shift, nbits, true, true));
                    return bit + shift;
                }

                mask <<= stride;
                shift += stride;
            } while (shift < 64);
        }
    }

    return INVALID_PHYSICAL;
}

u64 bitmap_alloc(bitmap b, int order)
{
    return bitmap_alloc_internal(b, U64_FROM_BIT(order), 0, b->maxbits);
}

/* Allocate 2^order bits, beginning search at offset - for randomized
   and next-fit allocations. offset will be aligned down to the lower
   order boundary.
*/
u64 bitmap_alloc_with_offset(bitmap b, int order, u64 offset)
{
    u64 off_align = offset & ~MASK(order);
    u64 nbits = U64_FROM_BIT(order);
    u64 bit = bitmap_alloc_internal(b, nbits, off_align, b->maxbits);
    if (bit == INVALID_PHYSICAL && off_align > 0)
        return bitmap_alloc_internal(b, nbits, 0, off_align);
    return bit;
}

boolean bitmap_dealloc(bitmap b, u64 bit, int order)
{
    u64 nbits = 1ull << order;
    u64 * mapbase = bitmap_base(b);
    assert(mapbase);

    /* XXX maybe error code instead of msg_err... */
    if (bit & (nbits - 1)) {
	msg_err("bitmap %p, bit %ld is not aligned to order %ld\n",
		b, bit, order);
	return false;
    }

    if (bit + nbits > b->maxbits) {
	msg_err("bitmap %p, bit %ld, order %ld: exceeds bit length %ld\n",
		b, bit, order, b->maxbits);
	return false;
    }

    if (!for_range_in_map(mapbase, bit, nbits, false, true)) {
	msg_err("bitmap %p, bit %ld, order %ld: not allocated in map; leaking\n",
		b, bit, order);
	return false;
    }

    for_range_in_map(mapbase, bit, nbits, true, false);
    return true;
}

static inline bitmap allocate_bitmap_internal(heap h, u64 length)
{
    assert(length > 0);
    bitmap b = allocate(h, sizeof(struct bitmap));
    if (b == INVALID_ADDRESS)
	return b;
    b->h = h;
    if (length == infinity)
	length = -1ull << 6; /* don't pad to 0 */
    b->maxbits = length;
    b->mapbits = MIN(ALLOC_EXTEND_BITS, pad(b->maxbits, 64));
    return b;
}

bitmap allocate_bitmap(heap h, u64 length)
{
    bitmap b = allocate_bitmap_internal(h, length);
    if (b == INVALID_ADDRESS)
	return b;
    u64 mapbytes = b->mapbits >> 3;
    b->alloc_map = allocate_buffer(h, mapbytes);
    if (b->alloc_map == INVALID_ADDRESS)
	return INVALID_ADDRESS;
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

bitmap bitmap_wrap(heap h, u64 * map, u64 length)
{
    bitmap b = allocate_bitmap_internal(h, length);
    if (b == INVALID_ADDRESS)
	return b;
    b->alloc_map = wrap_buffer(h, map, b->maxbits >> 3);
    if (b->alloc_map == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    return b;
}

void bitmap_unwrap(bitmap b)
{
    if (b->alloc_map)
	unwrap_buffer(b->h, b->alloc_map);
    deallocate(b->h, b, sizeof(struct bitmap));
}

bitmap bitmap_clone(bitmap b)
{
    bitmap c = allocate_bitmap_internal(b->h, b->maxbits);
    c->mapbits = b->mapbits;
    u64 mapbytes = c->mapbits >> 3;
    c->alloc_map = allocate_buffer(b->h, mapbytes);
    if (c->alloc_map == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    runtime_memcpy(buffer_ref(c->alloc_map, 0), buffer_ref(b->alloc_map, 0), mapbytes);
    buffer_produce(c->alloc_map, mapbytes);
    return c;
}

void bitmap_copy(bitmap dest, bitmap src)
{
    // XXX resize not needed yet
    assert(dest->maxbits == src->maxbits);
    assert(src->mapbits > 0);
    bitmap_extend(dest, src->mapbits - 1);
    runtime_memcpy(buffer_ref(dest->alloc_map, 0),
		   buffer_ref(src->alloc_map, 0),
		   src->mapbits >> 3);
    if (dest->mapbits > src->mapbits) {
	u64 off = src->mapbits >> 3;
	bytes len = (dest->mapbits - src->mapbits) >> 3;
	zero(buffer_ref(dest->alloc_map, off), len);
    }
}
