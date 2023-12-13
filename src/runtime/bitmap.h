#define BITMAP_WORDLEN_LOG      6
#define BITMAP_WORDLEN          (1 << BITMAP_WORDLEN_LOG)
#define BITMAP_WORDMASK         (BITMAP_WORDLEN - 1)

/* XXX keep allocs small for now; rolling heap allocations more than a
   page are b0rked */
#define ALLOC_EXTEND_BITS	U64_FROM_BIT(12)

typedef struct bitmap {
    u64 maxbits;
    u64 mapbits;
    heap meta;
    heap map;
    buffer alloc_map;
} *bitmap;

boolean bitmap_range_check_and_set(bitmap b, u64 start, u64 nbits, boolean validate, boolean set);
u64 bitmap_range_get_first(bitmap b, u64 start, u64 nbits);
u64 bitmap_alloc(bitmap b, u64 size);
u64 bitmap_alloc_within_range(bitmap b, u64 nbits, u64 start, u64 end);
boolean bitmap_dealloc(bitmap b, u64 bit, u64 size);
bitmap allocate_bitmap(heap meta, heap map, u64 length);
void deallocate_bitmap(bitmap b);
bitmap bitmap_wrap(heap h, u64 * map, u64 length);
void bitmap_unwrap(bitmap b);
bitmap bitmap_clone(bitmap b);
void bitmap_copy(bitmap dest, bitmap src);

#define bitmap_foreach_word(b, w, offset)				\
    for (u64 offset = 0, * __wp = bitmap_base(b), w = *__wp;		\
         offset < (b)->mapbits; offset += 64, w = *++__wp)

#define bitmap_word_foreach_set(w, bit, i, offset)			\
    for (u64 __w = (w), bit = lsb(__w), i = (offset) + (bit); __w;      \
         __w &= ~(1ull << (bit)), bit = lsb(__w), i = (offset) + (bit))

#define bitmap_foreach_set(b, i)					\
    bitmap_foreach_word((b), _w, s) bitmap_word_foreach_set(_w, __bit, (i), s)

static inline u64 *bitmap_base(bitmap b)
{
    return buffer_ref(b->alloc_map, 0);
}

/* no-op if i is within existing bounds, returns true if extended */
static inline boolean bitmap_extend(bitmap b, u64 i)
{
    if (i >= b->mapbits) {
        u64 mapbits = pad(i + 1, ALLOC_EXTEND_BITS);
        if (extend_total(b->alloc_map, mapbits >> 3)) {
            b->mapbits = mapbits;
            return true;
        }
    }
    return false;
}

static inline boolean bitmap_get(bitmap b, u64 i)
{
    if (i >= b->mapbits)
	return false;
    return (bitmap_base(b)[i >> 6] & (1ull << (i & 63))) != 0;
}

static inline void bitmap_set(bitmap b, u64 i, int val)
{
    if (i >= b->mapbits)
	assert(bitmap_extend(b, i));
    u64 mask = 1ull << (i & 63);
    u64 * p = bitmap_base(b) + (i >> 6);
    if (val)
	*p |= mask;
    else
	*p &= ~mask;
}

static inline void bitmap_set_atomic(bitmap b, u64 i, int val)
{
    u64 *p = bitmap_base(b) + (i >> 6);
    i &= MASK(6);
    if (val)
        atomic_set_bit(p, i);
    else
        atomic_clear_bit(p, i);
}

static inline int bitmap_test_and_set_atomic(bitmap b, u64 i, int val)
{
    u64 *p = bitmap_base(b) + (i >> 6);
    i &= MASK(6);
    if (val)
        return atomic_test_and_set_bit(p, i);
    else
        return atomic_test_and_clear_bit(p, i);
}
