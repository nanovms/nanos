/* bitmap allocator

   Allocations are aligned to next power-of-2 equal or greater than
   allocation size. This allows a simpler and faster allocation
   algorithm, and also has the side-effect of allowing mixed page
   sizes (e.g. 4K + 2M) within the same space.

   The bitmap length may be arbitrarily sized. The bitmap buffer is
   allocated in ALLOC_EXTEND_BITS / 8 byte increments as needed.
*/

#include <runtime.h>

#define BITMAP_WORDLEN_LOG      6
#define BITMAP_WORDLEN          (1 << BITMAP_WORDLEN_LOG)
#define BITMAP_WORDMASK         (BITMAP_WORDLEN - 1)

static inline u64 * pointer_from_bit(u64 * base, u64 bit)
{
    return base + (bit >> BITMAP_WORDLEN_LOG);
}

static inline boolean word_op(u64 * w, u64 mask, boolean set, boolean val)
{
    if (set) {
        *w = val ? *w | mask : *w & ~mask;
    } else {
        u64 masked = mask & *w;
        if ((val ? masked : (masked ^ mask)) != mask) {
            return false;
        }
    }
    return true;
}

static boolean for_range_in_map(u64 * base, u64 start, u64 nbits, boolean set, boolean val)
{
    u64 end = start + nbits;
    u64 head = start & BITMAP_WORDMASK;
    u64 tail = end & BITMAP_WORDMASK;

    if (nbits == 0)
        return true;

    /* for simplicity, always treat first word as a special case */
    u64 mask = -1ull;
    boolean single = head + nbits <= BITMAP_WORDLEN;

    if (head)
        mask &= ~MASK(head);

    if (tail && single)
        mask &= MASK(tail);

    boolean r = word_op(pointer_from_bit(base, start), mask, set, val);
    if (!r || single)
        return r;

    start += BITMAP_WORDLEN - head;

    u64 * w = pointer_from_bit(base, start);
    u64 * wend = pointer_from_bit(base, end & ~BITMAP_WORDMASK);

    for (; w < wend; w++) {
        if (!word_op(w, -1ull, set, val))
            return false;
    }

    if (tail) {
        if (!word_op(wend, MASK(tail), set, val))
            return false;
    }

    return true;
}

/* Requesting beyond the end of maxbits isn't an error; the caller may
   use it to avoid an additional range check.

   While bitmap_alloc() serves power-of-2 sized and aligned
   allocations, our reserve does not require such alignment. The two
   should co-exist without issue. */
boolean bitmap_range_check_and_set(bitmap b, u64 start, u64 nbits, boolean validate, boolean set)
{
    /* check both start and end in case of overflow / corrupt args */
    if (start >= b->maxbits || start + nbits > b->maxbits)
        return false;

    bitmap_extend(b, start + nbits - 1);
    u64 * mapbase = bitmap_base(b);
    return (!validate || for_range_in_map(mapbase, start, nbits, false, !set)) &&
        for_range_in_map(mapbase, start, nbits, true, set);
}

static inline u64 bitmap_alloc_internal(bitmap b, u64 nbits, u64 startbit, u64 endbit)
{
    int order = find_order(nbits);
    u64 stride = U64_FROM_BIT(order);
    endbit = MIN(endbit, b->maxbits);

    u64 bit = pad(startbit, stride);
    if (bit + nbits > endbit)
        return INVALID_PHYSICAL;

    u64 * mapbase = bitmap_base(b);

    endbit -= nbits;

    if (nbits >= 64) {
        /* multi-word */
        while (bit <= endbit) {
            if (bitmap_extend(b, bit + nbits))
                mapbase = bitmap_base(b);

            if (for_range_in_map(mapbase, bit, nbits, false, false)) {
                for_range_in_map(mapbase, bit, nbits, true, true);
                return bit;
            }

            bit += stride;
        }
    } else {
        for (; bit <= endbit; bit += 64) {
            /* get offset (for start bit, 0 otherwise) and align bit to word boundary */
            int word_offset = bit & 63;
            bit -= word_offset;
            if (bitmap_extend(b, bit + 64))
                mapbase = bitmap_base(b);

            u64 mask = MASK(nbits) << word_offset;
            u64 bw = *pointer_from_bit(mapbase, bit);

            if (bw == -1ull)    /* skip full words */
                continue;

            do {
                if (bit + word_offset > endbit)
                    return INVALID_PHYSICAL;

                if ((bw & mask) == 0) {
                    assert(for_range_in_map(mapbase, bit + word_offset, nbits, true, true));
                    return bit + word_offset;
                }

                mask <<= stride;
                word_offset += stride;
            } while (word_offset < 64);
        }
    }

    return INVALID_PHYSICAL;
}

u64 bitmap_alloc(bitmap b, u64 nbits)
{
    return bitmap_alloc_internal(b, nbits, 0, b->maxbits);
}

u64 bitmap_alloc_within_range(bitmap b, u64 nbits, u64 start, u64 end)
{
    return bitmap_alloc_internal(b, nbits, start, end);
}

boolean bitmap_dealloc(bitmap b, u64 bit, u64 size)
{
    int order = find_order(size);
    u64 * mapbase = bitmap_base(b);
    assert(mapbase);

    /* XXX maybe error code instead of msg_err... */
    if (bit & (size - 1)) {
	msg_err("bitmap %p, bit %ld is not aligned to order %ld\n",
		b, bit, order);
	return false;
    }

    if (bit + size > b->maxbits) {
	msg_err("bitmap %p, bit %ld, order %ld: exceeds bit length %ld\n",
		b, bit, order, b->maxbits);
	return false;
    }

    if (!for_range_in_map(mapbase, bit, size, false, true)) {
	msg_err("bitmap %p, bit %ld, order %ld: not allocated in map; leaking\n",
		b, bit, order);
	return false;
    }

    for_range_in_map(mapbase, bit, size, true, false);
    return true;
}

static inline bitmap allocate_bitmap_internal(heap meta, u64 length)
{
    assert(length > 0);
    bitmap b = allocate(meta, sizeof(struct bitmap));
    if (b == INVALID_ADDRESS)
	return b;
    b->meta = meta;
    if (length == infinity)
	length = -1ull << 6; /* don't pad to 0 */
    b->maxbits = length;
    b->mapbits = MIN(ALLOC_EXTEND_BITS, pad(b->maxbits, 64));
    return b;
}

bitmap allocate_bitmap(heap meta, heap map, u64 length)
{
    bitmap b = allocate_bitmap_internal(meta, length);
    if (b == INVALID_ADDRESS)
	return b;
    u64 mapbytes = b->mapbits >> 3;
    b->map = map;
    b->alloc_map = allocate_buffer(map, mapbytes);
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
    deallocate(b->meta, b, sizeof(struct bitmap));
}

bitmap bitmap_wrap(heap h, u64 * map, u64 length)
{
    bitmap b = allocate_bitmap_internal(h, length);
    if (b == INVALID_ADDRESS)
	return b;
    b->map = 0;
    b->alloc_map = wrap_buffer(h, map, b->maxbits >> 3);
    if (b->alloc_map == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    return b;
}

void bitmap_unwrap(bitmap b)
{
    if (b->alloc_map)
	unwrap_buffer(b->meta, b->alloc_map);
    deallocate(b->meta, b, sizeof(struct bitmap));
}

bitmap bitmap_clone(bitmap b)
{
    if (!b->map)           /* no wrapped, we'd need refcounts and all that crap */
        return INVALID_ADDRESS;
    bitmap c = allocate_bitmap_internal(b->meta, b->maxbits);
    c->mapbits = b->mapbits;
    u64 mapbytes = c->mapbits >> 3;
    c->alloc_map = allocate_buffer(b->map, mapbytes);
    if (c->alloc_map == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    c->map = b->map;
    c->meta = b->meta;
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
