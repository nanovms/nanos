#include <runtime.h>
#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define MAX_PAGE_ORDER	     12
#define LENGTH_ORDER	     16
#define RANDOM_TEST_PASSES   100
#define GTE_TEST_MAX	     512

static boolean basic_test(heap h)
{
    u64 base = 0x10000;
    u64 length = U64_FROM_BIT(LENGTH_ORDER);

    for (int page_order=0; page_order <= MAX_PAGE_ORDER; page_order++) {
	u64 pagesize = U64_FROM_BIT(page_order);
	u64 pages = length / pagesize;
	heap id = (heap)create_id_heap(h, h, base, length, pagesize, false);

	msg_debug("*** allocated id heap %p at length %ld (%ld pages), pagesize %ld\n",
		  id, pagesize * pages, pages, pagesize);

	for (int alloc_order=0; alloc_order <= (LENGTH_ORDER - page_order); alloc_order++) {
	    u64 n = U64_FROM_BIT(alloc_order);
	    msg_debug(">>> allocations of %ld page(s) ... ", n);

	    for (int i=0; i < pages; i += n) {
		u64 a = allocate_u64(id, pagesize * n);
		if (a == INVALID_PHYSICAL) {
		    msg_err("%s: allocation failed for page %ld", func_ss, i);
		    return false;
		}
		u64 expect = base + i * pagesize;
		if (a != expect) {
		    msg_err("%s: allocation for page %ld returned 0x%lx, expecting 0x%lx", func_ss,
			    i, a, expect);
		    return false;
		}
	    }

	    msg_debug("freeing...\n", pages, 1);

	    for (int i=0; i < pages; i += n) {
		u64 a = base + i * pagesize;
		deallocate_u64(id, a, pagesize * n);
	    }

	    /* Reset next-fit location for the current allocation size to avoid unexpected results for
	     * larger allocation sizes. */
	    id_heap_set_next((id_heap)id, pagesize * n, 0);
	}
	if (heap_allocated(id) > 0) {
	    msg_err("%s: heap allocated should be zero; fail", func_ss);
	    return false;
	}
        destroy_heap(id);
    }

    return true;
}

#define VEC_LEN 64
#define MAX_NPAGES_ORDER 8	/* up to 256 pages (4 bitmap words) */
static boolean random_test(heap h, heap rh, u64 page_order, int churn)
{
    //int max_order = page_order + MAX_NPAGES_ORDER;
    u64 alloc_size_vec[VEC_LEN];
    u64 alloc_result_vec[VEC_LEN];
    u64 pagesize = U64_FROM_BIT(page_order);

    for (int i=0; i < VEC_LEN; i++) {
	alloc_size_vec[i] = random_u64() & ((U64_FROM_BIT(MAX_NPAGES_ORDER) - 1) << page_order);
	if (alloc_size_vec[i] == 0)
	    alloc_size_vec[i] = pagesize;
    }

    zero(alloc_result_vec, VEC_LEN * sizeof(u64));

    heap id = (heap)create_id_heap_backed(h, h, rh, pagesize, false);
    msg_debug("*** allocated id heap %p, parent heap %p, pagesize %ld\n",
	      id, rh, pagesize);

    do {
	int start;

	start = random_u64() % VEC_LEN; /* change up start and end points */
	for (int i=0; i < VEC_LEN; i++) {
	    int o = (i + start) % VEC_LEN;
	    if (alloc_result_vec[o])
		continue;

	    alloc_result_vec[o] = allocate_u64(id, alloc_size_vec[o]);
	    msg_debug("alloc %d, size %ld, result %lx\n", o, alloc_size_vec[o], alloc_result_vec[o]);
	    if (alloc_result_vec[o] == INVALID_PHYSICAL) {
		msg_err("%s: alloc of size %ld failed", func_ss, alloc_size_vec[o]);
		goto fail;
	    }
	}

	/* now check that no allocations overlap */
	for (int i=0; i < VEC_LEN; i++) {
	    for (int j=0; j < VEC_LEN; j++) {
		if (i == j)
		    continue;

		u64 i_first = alloc_result_vec[i];
		u64 i_last = alloc_result_vec[i] + alloc_size_vec[i] - 1;
		u64 j_first = alloc_result_vec[j];
		u64 j_last = alloc_result_vec[j] + alloc_size_vec[j] - 1;

		if ((i_first >= j_first && i_first <= j_last) ||
		    (i_last >= j_first && i_last <= j_last)) {
		    msg_err("%s error: results %d and %d intersect", func_ss, i, j);
		    goto fail;
		}
	    }
	}

	/* free */
	start = random_u64() % VEC_LEN;
	for (int i=0; i < VEC_LEN; i++) {
	    /* selectively deallocate if multiple passes */
	    if (churn > 0 && (random_u64() & 0x1))
		continue;
	    int o = (i + start) % VEC_LEN;
	    if (alloc_result_vec[o]) {
		msg_debug("dealloc %d, size %ld\n", o, alloc_size_vec[o]);
		deallocate_u64(id, alloc_result_vec[o], alloc_size_vec[o]);
		alloc_result_vec[o] = 0;
	    }
	}
    } while(churn-- > 0);

    if (heap_allocated(id) > 0) {
	msg_err("%s: heap allocated (%d) should be zero; fail", func_ss, heap_allocated(id));
	return false;
    }
    destroy_heap(id);
    return true;
  fail:
    msg_err("%s error: test vector:\ni\t(alloc,\tresult)", func_ss);
    for (int i=0; i < VEC_LEN; i++) {
        msg_err("%d\t(%ld,\t%lx)", i, alloc_size_vec[i], alloc_result_vec[i]);
    }
    return false;
}

#define N_RANGES	4
static u64 ranges[N_RANGES] = { 0x100000000ull,
				0x200000000ull,
				0x300000000ull,
				0x400000000ull };
static int curr_range;

u64 rangeheap_alloc(heap h, bytes size)
{
    assert(size == h->pagesize);
    if (curr_range == N_RANGES)
	return INVALID_PHYSICAL;
    return ranges[curr_range++];
}

heap allocate_rangeheap(heap meta, bytes pagesize)
{
    heap h = allocate(meta, sizeof(struct heap));
    h->alloc = rangeheap_alloc;
    h->dealloc = leak;
    h->pagesize = pagesize;
    h->allocated = 0;
    h->total = 0;
    return h;
}

static boolean alloc_gte_test(heap h)
{
    id_heap idh = create_id_heap(h, h, 0, GTE_TEST_MAX, 1, false);
    if (idh == INVALID_ADDRESS) {
        msg_err("%s error: cannot create heap", func_ss);
        return false;
    }
    if (id_heap_alloc_gte(idh, 1, GTE_TEST_MAX) != INVALID_PHYSICAL) {
        msg_err("%s error: allocation should have failed for id %ld", func_ss, GTE_TEST_MAX);
        return false;
    }
    for (u64 id = 0; id < GTE_TEST_MAX; id++) {
        u64 allocated = id_heap_alloc_gte(idh, 1, id);
        if (allocated != id) {
            if (allocated == INVALID_PHYSICAL) {
                msg_err("%s: allocation failed for id %ld", func_ss, id);
                return false;
            }
            else {
                msg_err("%s error: allocation returned %ld, expecting %ld", func_ss, allocated,
                        id);
                return false;
            }
        }
    }
    for (u64 id = 0; id < GTE_TEST_MAX; id++) {
        deallocate_u64((heap)idh, id, 1);
    }
    for (u64 id = GTE_TEST_MAX - 1; (s64)id >= 0; id--) {
        u64 allocated = id_heap_alloc_gte(idh, 1, id);
        if (allocated != id) {
            if (allocated == INVALID_PHYSICAL) {
                msg_err("%s: allocation failed for id %ld", func_ss, id);
                return false;
            }
            else {
                msg_err("%s error: allocation returned %ld, expecting %ld", func_ss, allocated,
                        id);
                return false;
            }
        }
    }
    for (u64 id = 0; id < GTE_TEST_MAX; id++) {
        deallocate_u64((heap)idh, id, 1);
    }
    for (u64 id = 0; ; id++) {
        u64 allocated = id_heap_alloc_gte(idh, 1, 0);
        if (allocated == INVALID_PHYSICAL) {
            if (id != GTE_TEST_MAX) {
                msg_err("%s: allocation failed for id %ld", func_ss, id);
                return false;
            }
            break;
        }
        else if (id == GTE_TEST_MAX) {
            msg_err("%s error: allocation should have failed for id %ld", func_ss, GTE_TEST_MAX);
            return false;
        }
    }
    for (u64 id = GTE_TEST_MAX - 1; (s64)id >= 0; id--) {
        deallocate_u64((heap)idh, id, 1);
    }
    if (heap_allocated((heap)idh) > 0) {
        msg_err("%s error: non-zero heap allocated (%d)", func_ss, heap_allocated((heap)idh));
        return false;
    }
    destroy_heap((heap)idh);

    idh = create_id_heap(h, h, 1, 2, 1, false);
    if (idh == INVALID_ADDRESS) {
        msg_err("%s error: cannot create heap", func_ss);
        return false;
    }
    u64 id = id_heap_alloc_gte(idh, 1, 1);
    if (id != 1) {
        msg_err("%s error: allocation returned %ld, expecting 1", func_ss, id);
        return false;
    }
    deallocate_u64((heap)idh, id, 1);
    destroy_heap((heap)idh);

    return true;
}

#define SUBRANGE_TEST_MIN         (8 * PAGESIZE)
#define SUBRANGE_TEST_LENGTH      (16 * PAGESIZE)
#define SUBRANGE_TEST_END         (SUBRANGE_TEST_MIN + SUBRANGE_TEST_LENGTH)
#define SUBRANGE_TEST_INIT_ALLOCS 4

static boolean alloc_subrange_test(heap h)
{
    build_assert((SUBRANGE_TEST_LENGTH % 4) == 0);

    id_heap id = create_id_heap(h, h, SUBRANGE_TEST_MIN, SUBRANGE_TEST_LENGTH, PAGESIZE, false);
    if (id == INVALID_ADDRESS) {
        msg_err("%s error: cannot create heap", func_ss);
        return false;
    }

    /* these should fail */
    if (id_heap_alloc_subrange(id, PAGESIZE, 0, SUBRANGE_TEST_MIN) != INVALID_PHYSICAL) {
        msg_err("%s error: should have failed for lower non-intersecting subrange", func_ss);
        return false;
    }

    if (id_heap_alloc_subrange(id, 1, SUBRANGE_TEST_END - PAGESIZE + 1,
                               SUBRANGE_TEST_END + PAGESIZE) != INVALID_PHYSICAL) {
        msg_err("%s error: should have failed for upper non-intersecting subrange", func_ss);
        return false;
    }

    if (id_heap_alloc_subrange(id, PAGESIZE, SUBRANGE_TEST_MIN + PAGESIZE + 1,
                               SUBRANGE_TEST_MIN + 2 * PAGESIZE + 1) != INVALID_PHYSICAL) {
        msg_err("%s error: should have failed for unaligned subrange", func_ss);
        return false;
    }

    int pages_remaining = SUBRANGE_TEST_LENGTH / PAGESIZE;
    /* test alloc within unaligned range */
    int alloc_size = 1;
    int allocs = SUBRANGE_TEST_INIT_ALLOCS - 1; /* subtract skipped page from head align */
    u64 expect = SUBRANGE_TEST_MIN + PAGESIZE;
    u64 start = SUBRANGE_TEST_MIN + 1;
    u64 end = SUBRANGE_TEST_MIN + (allocs + 1) * PAGESIZE + 1;
    u64 res;
    for (int i = 0; i < allocs; i++) {
        if ((res = id_heap_alloc_subrange(id, alloc_size, start, end)) != expect) {
            msg_err("%s error: subrange alloc expected 0x%lx, got 0x%lx", func_ss, expect, res);
            return false;
        }
        pages_remaining--;
        expect += PAGESIZE;
    }
    if ((res = id_heap_alloc_subrange(id, alloc_size, start, end)) != INVALID_PHYSICAL) {
        msg_err("%s error: superfluous subrange alloc did not fail, got 0x%lx", func_ss, res);
        return false;
    }

    /* test multi-page (but not power-of-2) alloc with range not multiple of alignment */
    alloc_size = 3 * PAGESIZE;
    allocs = ((SUBRANGE_TEST_LENGTH / PAGESIZE) - SUBRANGE_TEST_INIT_ALLOCS) / 4;
    start = end - 1;
    expect = pad(start, 4 * PAGESIZE);
    end = expect + (allocs - 1) * (4 * PAGESIZE) + (3 * PAGESIZE);

    for (int i = 0; i < allocs; i++) {
        if ((res = id_heap_alloc_subrange(id, alloc_size, start, end)) != expect) {
            msg_err("%s error: multi-page subrange alloc expected 0x%lx, got 0x%lx",
                    func_ss, expect, res);
            return false;
        }
        pages_remaining -= 3;
        expect += 4 * PAGESIZE;
    }
    if ((res = id_heap_alloc_subrange(id, alloc_size, start, end)) != INVALID_PHYSICAL) {
        msg_err("%s error: multi-page superfluous subrange alloc should have failed, got 0x%lx",
                func_ss, res);
        return false;
    }

    /* we should have a remainder page for each 3-page alloc plus the skipped page above */
    if (pages_remaining != allocs + 1) {
        msg_err("%s error: pages_remaining %d, should be %d", func_ss, pages_remaining, allocs + 1);
        return false;
    }

    for (int i = 0; i < pages_remaining; i++) {
        if (i < allocs)
            /* Next fit for minimum-sized allocations should pick up from the first set of
             * allocations and fill the gaps between allocations in the second set. */
            expect = start + alloc_size + i * U64_FROM_BIT(find_order(alloc_size));
        else
            expect = SUBRANGE_TEST_MIN; /* should wrap around and pick up skipped page from above */

        if ((res = allocate_u64((heap)id, PAGESIZE)) != expect) {
            msg_err("%s error: remainder alloc returned 0x%lx, should be 0x%lx (iter %d)",
                    func_ss, res, expect, i);
            return false;
        }
    }

    /* we should have exhausted the number space */
    if ((res = allocate_u64((heap)id, PAGESIZE)) != INVALID_PHYSICAL) {
        msg_err("%s error: should have exhausted number space, got 0x%lx", func_ss, res);
        return false;
    }

    destroy_heap((heap)id);
    return true;
}

static boolean alloc_align_test(heap h)
{
    const u64 unaligned_base = 0x12345;
    const u64 heap_size = 0x20000;
    id_heap id = create_id_heap(h, h, unaligned_base, heap_size, 1, false);
    if (id == INVALID_ADDRESS) {
        msg_err("%s failed to create heap", func_ss);
        return false;
    }
    for (int size = 1; pad(unaligned_base, size) + size <= unaligned_base + heap_size; size <<= 1) {
        u64 i = allocate_u64((heap)id, size);
        if (i != pad(unaligned_base, size)) {
            msg_err("%s error: unexpected allocation 0x%lx for size 0x%x", func_ss, i, size);
            return false;
        }
        deallocate_u64((heap)id, i, size);
    }
    destroy_heap((heap)id);
    return true;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
	goto fail;

    heap rh = allocate_rangeheap(h,
				 U64_FROM_BIT(MAX_PAGE_ORDER + MAX_NPAGES_ORDER)
				 * 64 / N_RANGES);
    for (int order=0; order <= MAX_PAGE_ORDER; order++) {
	curr_range = 0;
	if (!random_test(h, rh, order, RANDOM_TEST_PASSES))
	    goto fail;
    }

    if (!alloc_gte_test(h))
        goto fail;

    if (!alloc_subrange_test(h))
        goto fail;

    if (!alloc_align_test(h))
        goto fail;

    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("Id heap test failed");
    exit(EXIT_FAILURE);
}
