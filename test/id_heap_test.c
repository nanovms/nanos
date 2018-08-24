#include <runtime.h>
#include <stdlib.h>

#define MAX_PAGE_ORDER	12
#define LENGTH_ORDER	16

static boolean basic_test(heap h)
{
    u64 base = 0x10000;
    u64 length = 1 << LENGTH_ORDER;

    for (int page_order=0; page_order <= MAX_PAGE_ORDER; page_order++) {
	u64 pagesize = 1 << page_order;
	u64 pages = length / pagesize;
	heap id = create_id_heap(h, base, length, pagesize);

	msg_debug("*** allocated id heap %p at length %d (%d pages), pagesize %d\n",
		  id, pagesize * pages, pages, pagesize);

	for (int alloc_order=0; alloc_order <= (LENGTH_ORDER - page_order); alloc_order++) {
	    u64 n = 1 << alloc_order;
	    msg_debug(">>> allocations of %d page(s) ... ", n);

	    for (int i=0; i < pages; i += n) {
		u64 a = allocate_u64(id, pagesize * n);
		if (a == INVALID_PHYSICAL) {
		    msg_err("!!! allocation failed for page %d\n", i);
		    return false;
		}
		u64 expect = base + i * pagesize;
		if (a != expect) {
		    msg_err("!!! allocation for page %d returned %P, expecting %P\n",
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

	id->destroy(id);
    }

    return true;
}

#define VEC_LEN 64
static boolean random_test(heap h, u64 page_order)
{
    int max_order = page_order + 4; /* up to 16 pages; arbitrary */
    int alloc_size_vec[VEC_LEN];
    u64 alloc_result_vec[VEC_LEN];
    u64 length = (1 << max_order) * VEC_LEN;
    u64 pagesize = 1 << page_order;

    for (int i=0; i < VEC_LEN; i++) {
	alloc_size_vec[i] = random_u64() & (((1 << (max_order - page_order)) - 1) << page_order);
	if (alloc_size_vec[i] == 0)
	    alloc_size_vec[i] = pagesize;
    }

    zero(alloc_result_vec, VEC_LEN * sizeof(u64));

    heap id = create_id_heap(h, 0, length, pagesize);

    msg_debug("*** allocated id heap %p at length %d (%d pages), pagesize %d\n",
	    id, length, length / pagesize, pagesize);

    for (int i=0; i < VEC_LEN; i++) {
	alloc_result_vec[i] = allocate_u64(id, alloc_size_vec[i]);
	if (alloc_result_vec[i] == INVALID_PHYSICAL) {
	    msg_err("alloc of size %d failed\n", alloc_size_vec[i]);
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
    for (int i=0; i < VEC_LEN; i++) {
	deallocate_u64(id, alloc_result_vec[i], alloc_size_vec[i]);
    }

    id->destroy(id);

    return true;
  fail:
    msg_err("test vector:\ni\t(alloc,\tresult)\n");
    for (int i=0; i < VEC_LEN; i++) {
	rprintf("%d\t(%d,\t%P)\n", i, alloc_size_vec[i], alloc_result_vec[i]);
    }
    return false;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
	goto fail;

    for (int order=0; order < 13; order++) {
	if (!random_test(h, order))
	    goto fail;
    }

    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("test failed\n");
    exit(EXIT_FAILURE);
}
