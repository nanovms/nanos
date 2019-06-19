#include <runtime.h>
#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define MAX_PAGE_ORDER		12
#define LENGTH_ORDER		16
#define RANDOM_TEST_PASSES	100
#define GTE_TEST_MAX		512

static boolean basic_test(heap h)
{
    u64 base = 0x10000;
    u64 length = U64_FROM_BIT(LENGTH_ORDER);

    for (int page_order=0; page_order <= MAX_PAGE_ORDER; page_order++) {
	u64 pagesize = U64_FROM_BIT(page_order);
	u64 pages = length / pagesize;
	heap id = create_id_heap(h, base, length, pagesize);

	msg_debug("*** allocated id heap %p at length %ld (%ld pages), pagesize %ld\n",
		  id, pagesize * pages, pages, pagesize);

	for (int alloc_order=0; alloc_order <= (LENGTH_ORDER - page_order); alloc_order++) {
	    u64 n = U64_FROM_BIT(alloc_order);
	    msg_debug(">>> allocations of %ld page(s) ... ", n);

	    for (int i=0; i < pages; i += n) {
		u64 a = allocate_u64(id, pagesize * n);
		if (a == INVALID_PHYSICAL) {
		    msg_err("!!! allocation failed for page %ld\n", i);
		    return false;
		}
		u64 expect = base + i * pagesize;
		if (a != expect) {
		    msg_err("!!! allocation for page %ld returned %lx, expecting %lx\n",
			    i, a, expect);
		    return false;
		}
	    }

	    msg_debug("freeing...\n", pages, 1);

	    for (int i=0; i < pages; i += n) {
		u64 a = base + i * pagesize;
		deallocate_u64(id, a, pagesize * n);
	    }
	}
	if (id->allocated > 0) {
	    msg_err("heap allocated should be zero; fail\n");
	    return false;
	}
	id->destroy(id);
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

    heap id = create_id_heap_backed(h, rh, pagesize);
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
		msg_err("alloc of size %ld failed\n", alloc_size_vec[o]);
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
		    msg_err("results %d and %d intersect\n", i, j);
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

    if (id->allocated > 0) {
	msg_err("heap allocated (%d) should be zero; fail\n", id->allocated);
	return false;
    }
    id->destroy(id);

    return true;
  fail:
    msg_err("test vector:\ni\t(alloc,\tresult)\n");
    for (int i=0; i < VEC_LEN; i++) {
	rprintf("%d\t(%ld,\t%lx)\n", i, alloc_size_vec[i], alloc_result_vec[i]);
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
    return h;
}

static boolean alloc_gte_test(heap h)
{
    heap idh = create_id_heap(h, 0, GTE_TEST_MAX, 1);
    if (idh == INVALID_ADDRESS) {
        msg_err("cannot create heap\n");
        return false;
    }
    if (id_heap_alloc_gte(idh, GTE_TEST_MAX) != INVALID_PHYSICAL) {
        msg_err("allocation should have failed for id %ld\n", GTE_TEST_MAX);
        return false;
    }
    for (u64 id = 0; id < GTE_TEST_MAX; id++) {
        u64 allocated = id_heap_alloc_gte(idh, id);
        if (allocated != id) {
            if (allocated == INVALID_PHYSICAL) {
                msg_err("allocation failed for id %ld\n", id);
                return false;
            }
            else {
                msg_err("allocation returned %ld, expecting %ld\n", allocated,
                        id);
                return false;
            }
        }
    }
    for (u64 id = 0; id < GTE_TEST_MAX; id++) {
        deallocate_u64(idh, id, 1);
    }
    for (u64 id = GTE_TEST_MAX - 1; (s64)id >= 0; id--) {
        u64 allocated = id_heap_alloc_gte(idh, id);
        if (allocated != id) {
            if (allocated == INVALID_PHYSICAL) {
                msg_err("allocation failed for id %ld\n", id);
                return false;
            }
            else {
                msg_err("allocation returned %ld, expecting %ld\n", allocated,
                        id);
                return false;
            }
        }
    }
    for (u64 id = 0; id < GTE_TEST_MAX; id++) {
        deallocate_u64(idh, id, 1);
    }
    for (u64 id = 0; ; id++) {
        u64 allocated = id_heap_alloc_gte(idh, 0);
        if (allocated == INVALID_PHYSICAL) {
            if (id != GTE_TEST_MAX) {
                msg_err("allocation failed for id %ld\n", id);
                return false;
            }
            break;
        }
        else if (id == GTE_TEST_MAX) {
            msg_err("allocation should have failed for id %ld\n", GTE_TEST_MAX);
            return false;
        }
    }
    for (u64 id = GTE_TEST_MAX - 1; (s64)id >= 0; id--) {
        deallocate_u64(idh, id, 1);
    }
    if (idh->allocated > 0) {
        msg_err("heap allocated is %d, should be zero\n", idh->allocated);
        return false;
    }
    idh->destroy(idh);
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

    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("test failed\n");
    exit(EXIT_FAILURE);
}
