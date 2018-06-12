typedef struct rtrie *rtrie;
typedef closure_type(subrange, void, u64, u64);
void rtrie_range_lookup(rtrie r, u64 start, u64 length, subrange s);
void *rtrie_lookup(rtrie r, u64 point);
void rtrie_insert(rtrie r, u64 start, u64 length, void *value);
void rtrie_extents(rtrie r, u64 *min, u64 *max);
rtrie rtrie_create(heap h);
void rtrie_extent(rtrie r, u64 *min, u64 *max);

