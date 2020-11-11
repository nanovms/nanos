#include <runtime.h>
#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define WHOLE_RANGE irange(0, infinity)


/**
 * Inspired by id_alloc_from_range in id.c
 * Returns a bitmap to further test on.
 */
u64 test_alloc(id_heap i, id_range r, u64 pages, range subrange) {
    id_debug("id range %R, pages %ld, subrange %R\n", r->n.r, pages, subrange);
    u64 pages_rounded = U64_FROM_BIT(find_order(pages)); /* maintain 2^n alignment */

    /* find intersection, align start and end to 2^n and subtract range offset */
    range ri = range_intersection(r->n.r, subrange);
    id_debug("intersection %R, pages_rounded %ld\n", ri, pages_rounded);
    if (range_empty(ri))
        return INVALID_PHYSICAL;

    /* align search start (but not end, for pages may fit in a
       non-power-of-2 remainder at the end of the range) and remove
       id_range offset */
    ri.start = pad(ri.start, pages_rounded) - r->n.r.start;
    ri.end -= r->n.r.start;
    id_debug("after adjust %R\n", ri);
    if (!range_valid(ri) || range_span(ri) < pages) {
        id_debug("range invalid %d, range_span(ri) %ld, pages %ld\n",
                 range_valid(ri), range_span(ri), pages);
        return INVALID_PHYSICAL;
    }

    /* check for randomization, else check for next fit */
    u64 max_start = range_span(ri) > pages_rounded ?
        (range_span(ri) & ~(pages_rounded - 1)) - pages_rounded : 0;
    u64 start_bit = ri.start;
    if ((i->flags & ID_HEAP_FLAG_RANDOMIZE) && max_start > 0)
        start_bit += random_u64() % max_start;
    else if (point_in_range(ri, r->next_bit))
        start_bit = r->next_bit;

    id_debug("start_bit 0x%lx, end 0x%lx\n", start_bit, ri.end);
    /* search beginning at start_bit, wrapping around if needed */
    u64 bit = bitmap_alloc_within_range(r->b, pages, start_bit, ri.end);
    if (bit == INVALID_PHYSICAL && start_bit > ri.start)
        bit = bitmap_alloc_within_range(r->b, pages, ri.start, start_bit);
    return bit;
}

/**
 *  Tests the cloning functionality of bitmaps. 
 */
boolean test_clone(bitmap b) {
    u64 b_cpy = bitmap_clone(b);
    return (b_cpy == b);
}

boolean basic_test(heap h)
{
    // from id_alloc in id.c
    id_heap i = (id_heap)h;
    u64 pages = pages_from_bytes(i, 1); // 1 is from alloc_subrange_test
    id_range r = (id_range)rangemap_first_node(i->ranges);
    u64 b = test_alloc(i, r, pages, WHOLE_RANGE);
    if (bit == INVALID_PHYSICAL)
        //TODO: error check

    // tests bitmap cloning
    if (!test_clone(b)) {
        msg_err("cloning bitmap failed.");
        return false;
    }


}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    basic_test(h);

}



