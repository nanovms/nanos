/* This test is only suitable for the sorted list implementation. It
   will need doctoring if the behavior of range search, etc., changes. */

//#define ENABLE_MSG_DEBUG
#include <runtime.h>

#include "../test_utils.h"

struct rm_result {
    range r;
    int val;
};

/* XXX restore to original glory */
static struct rm_result rm_results[] = {
    { irange(10, 20), 1 },
    { irange(20, 30), 3 } };

typedef struct test_node {
    struct rmnode node;
    int val;
} *test_node;

closure_func_basic(rmnode_handler, boolean, basic_test_validate,
                   rmnode node)
{
    static int count = 0;
    int nresults = sizeof(rm_results) / sizeof(struct rm_result);
    range r = range_from_rmnode(node);
    int val = ((test_node)node)->val;
    if (count >= nresults) {
        msg_err("%s error: range lookup extraneous result: %R, %p", func_ss, r, val);
        exit(EXIT_FAILURE);
    }
    if (!range_equal(r, rm_results[count].r) || val != rm_results[count].val) {
        msg_err("%s error: count %d, range lookup result mismatch, expected %R, %d, got %R, %d",
                func_ss, count, rm_results[count].r, rm_results[count].val, r, val);
        exit(EXIT_FAILURE);
    }
    count++;
    return true;
}

static test_node allocate_test_node(heap h, range r, int val)
{
    test_node tn = allocate(h, sizeof(struct test_node));
    if (tn == INVALID_ADDRESS) {
        test_error("unable to allocate test node");
    }
    rmnode_init(&tn->node, r);
    tn->val = val;
    return tn;
}

closure_function(1, 1, boolean, dealloc_test_node,
                 heap, h,
                 rmnode n)
{
    deallocate(bound(h), n, sizeof(struct test_node));
    return true;
}

boolean basic_test(heap h)
{
    char * msg = "";
    rangemap rm = allocate_rangemap(h);
    if (rm == INVALID_ADDRESS) {
        msg_err("%s failed to allocate rangemap", func_ss);
        return false;
    }

    boolean rv;
    test_node tn1 = allocate_test_node(h, irange(10, 20), 1);
    if (!tn1) {
        msg = "alloc 0";
        goto fail;
    }

    rv = rangemap_insert(rm, &tn1->node);
    if (!rv) {
        msg = "insert 0";
        goto fail;
    }

    /* should fail, overlap of one */
    test_node tn2 = allocate_test_node(h, irange(19, 20), 2);
    if (!tn2) {
        msg = "alloc 1";
        goto fail;
    }

    rv = rangemap_insert(rm, &tn2->node);
    if (rv) {
        msg = "insert 1";
        goto fail;
    }

    /* should pass, abut first range */
    test_node tn3 = allocate_test_node(h, irange(20, 30), 3);
    if (!tn3) {
        msg = "alloc 3";
        goto fail;
    }

    rv = rangemap_insert(rm, &tn3->node);
    if (!rv) {
        msg = "insert 2";
        goto fail;
    }

    /* basic lookup (pass) */
    if (rangemap_lookup(rm, 19) != &tn1->node) {
        msg = "lookup 0";
        goto fail;
    }

    /* lookup in hole (fail) */
    if (rangemap_lookup(rm, 9) != INVALID_ADDRESS) {
        msg = "lookup 1";
        goto fail;
    }

    /* lookup next range (pass) */
    if (rangemap_lookup(rm, 19) != &tn1->node) {
        msg = "lookup 2";
        goto fail;
    }

    /* range lookup */
    rmnode_handler rh = stack_closure_func(rmnode_handler, basic_test_validate);
    rangemap_range_lookup(rm, irange(0, 26), rh);
    return true;

  fail:
    deallocate_rangemap(rm, stack_closure(dealloc_test_node, h));
    printf("rangemap basic test failed: %s\n", msg);
    return false;
}

static boolean range_diff_test(void)
{
    range a, b, d1, d2;
    a.start = 10;
    a.end = 20;
    b.start = 9;
    b.end = 10;
    range_difference(a, b, &d1, &d2);
    if ((d1.start != a.start) || (d1.end != a.end) || !range_empty(d2))
        return false;
    b.end = 12;
    range_difference(a, b, &d1, &d2);
    if (range_empty(d1)) {
        if ((d2.start != b.end) || (d2.end != a.end))
            return false;
    } else {
        if ((d1.start != b.end) || (d1.end != a.end) || !range_empty(d2))
            return false;
    }
    b.start = 11;
    range_difference(a, b, &d1, &d2);
    if ((d1.start != a.start) || (d1.end != b.start) || (d2.start != b.end) || (d2.end != a.end))
        return false;
    b.end = 21;
    range_difference(a, b, &d1, &d2);
    if ((d1.start != a.start) || (d1.end != b.start) || !range_empty(d2))
        return false;
    b.start = 20;
    range_difference(a, b, &d1, &d2);
    if ((d1.start != a.start) || (d1.end != a.end) || !range_empty(d2))
        return false;
    b.start = 9;
    range_difference(a, b, &d1, &d2);
    if (!range_empty(d1) || !range_empty(d2))
        return false;
    return true;
}

static void rangemap_verify_ranges(rangemap rm, int expected_count, u64 expected_length)
{
    int count = 0;
    u64 length = 0;
    u64 previous_end = 0;
    rangemap_foreach(rm, n) {
        if ((count++ > 0) && (n->r.start <= previous_end)) {
            msg_err("%s error: unexpected range %R, previous end %ld)",
                    func_ss, n->r, previous_end);
            exit(EXIT_FAILURE);
        }
        length += range_span(n->r);
    }
    if ((count != expected_count) || (length != expected_length)) {
        test_error("range count %d (expected %d), length %lld (expected %lld)",
                count, expected_count, length, expected_length);
    }
}

closure_function(1, 1, boolean, rangemap_merge_destructor,
                 heap, h,
                 rmnode n)
{
    deallocate(bound(h), n, sizeof(*n));
    return true;
}

static boolean rangemap_merge_test(heap h)
{
    rangemap rm = allocate_rangemap(h);
    if (rm == INVALID_ADDRESS) {
        msg_err("%s failed to allocate rangemap", func_ss);
        return false;
    }
    rangemap_verify_ranges(rm, 0, 0);
    rangemap_insert_range(rm, irange(1, 2));
    rangemap_verify_ranges(rm, 1, 1);
    rangemap_insert_range(rm, irange(3, 4));
    rangemap_verify_ranges(rm, 2, 2);
    rangemap_insert_range(rm, irange(2, 3));
    rangemap_verify_ranges(rm, 1, 3);
    rangemap_insert_range(rm, irange(4, 5));
    rangemap_verify_ranges(rm, 1, 4);
    rangemap_insert_range(rm, irange(7, 8));
    rangemap_verify_ranges(rm, 2, 5);
    rangemap_insert_range(rm, irange(6, 7));
    rangemap_verify_ranges(rm, 2, 6);
    rangemap_insert_range(rm, irange(1, 9));
    rangemap_verify_ranges(rm, 1, 8);
    rangemap_insert_range(rm, irange(0, 10));
    rangemap_verify_ranges(rm, 1, 10);
    rangemap_insert_range(rm, irange(0, 1));
    rangemap_verify_ranges(rm, 1, 10);
    rangemap_insert_range(rm, irange(1, 2));
    rangemap_verify_ranges(rm, 1, 10);
    rangemap_insert_range(rm, irange(9, 10));
    rangemap_verify_ranges(rm, 1, 10);
    rangemap_insert_range(rm, irange(9, 11));
    rangemap_verify_ranges(rm, 1, 11);
    rangemap_insert_range(rm, irange(12, 14));
    rangemap_verify_ranges(rm, 2, 13);
    rangemap_insert_range(rm, irange(10, 13));
    rangemap_verify_ranges(rm, 1, 14);
    deallocate_rangemap(rm, stack_closure(rangemap_merge_destructor, h));
    return true;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
        goto fail;

    if (!range_diff_test())
        goto fail;

    if (!rangemap_merge_test(h))
        goto fail;

    msg_debug("range test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("Range test failed");
    exit(EXIT_FAILURE);
}
