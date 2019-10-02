/* This test is only suitable for the sorted list implementation. It
   will need doctoring if the behavior of range search, etc., changes. */

//#define ENABLE_MSG_DEBUG
#include <stdio.h>
#include <runtime.h>
#include <stdlib.h>

struct rm_result {
    range r;
    int val;
};

/* XXX restore to original glory */
static struct rm_result rm_results[] = {
    { irange(15, 20), 1 },
    { irange(20, 25), 3 } };

typedef struct test_node {
    struct rmnode node;
    int val;
} *test_node;

closure_function(0, 1, void, basic_test_validate,
                 rmnode, node)
{
    static int count = 0;
    int nresults = sizeof(rm_results) / sizeof(struct rm_result);
    range r = range_from_rmnode(node);
    int val = ((test_node)node)->val;
    if (count >= nresults) {
        msg_err("range lookup extraneous result: %R, %p\n", r, val);
        exit(EXIT_FAILURE);
    }
    if (!range_equal(r, rm_results[count].r) || val != rm_results[count].val) {
        msg_err("count %d, range lookup result mismatch, expected %R, %d but got %R, %d\n",
                count, rm_results[count].r, rm_results[count].val, r, val);
        exit(EXIT_FAILURE);
    }
    count++;
}

static test_node allocate_test_node(heap h, range r, int val)
{
    test_node tn = allocate(h, sizeof(struct test_node));
    if (tn == INVALID_ADDRESS) {
        printf("unable to allocate test node; fail\n");
        exit(EXIT_FAILURE);
    }
    rmnode_init(&tn->node, r);
    tn->val = val;
    return tn;
}

/* XXX do node free */

boolean basic_test(heap h)
{
    char * msg = "";
    rangemap rm = allocate_rangemap(h);
    if (rm == INVALID_ADDRESS) {
        msg_err("failed to allocate rangemap\n");
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

    /* test partial delete (head trim) */
    if (!rangemap_remove_range(rm, (range){5, 15})) {
        msg = "remove 0 - no match";
        goto fail;
    }

    /* should fail */
    if (rangemap_lookup(rm, 14) != INVALID_ADDRESS) {
        msg = "remove 0 - lookup 0";
        goto fail;
    }

    /* pass */
    if (rangemap_lookup(rm, 15) != &tn1->node) {
        msg = "remove 0 - lookup 1";
        goto fail;
    }

    /* test partial delete (tail trim) */
    if (!rangemap_remove_range(rm, (range){25, 31})) {
        msg = "remove 1 - no match";
        goto fail;
    }

    /* should fail */
    if (rangemap_lookup(rm, 25) != INVALID_ADDRESS) {
        msg = "remove 1 - lookup 0";
        goto fail;
    }

    if (rangemap_lookup(rm, 29) != INVALID_ADDRESS) {
        msg = "remove 1 - lookup 1";
        goto fail;
    }

    /* pass */
    if (rangemap_lookup(rm, 24) != &tn3->node) {
        msg = "remove 1 - lookup 2";
        goto fail;
    }

#if 0
    /* test partial delete (hole trim) */
    rv = rangemap_remove_range(rm, (range){21, 24});
    if (!rv) {
        msg = "remove 2 - no match";
        goto fail;
    }

    /* should fail */
    if (rangemap_lookup(rm, 21, &r) != INVALID_ADDRESS) {
        msg = "remove 2 - lookup 0";
        goto fail;
    }

    if (rangemap_lookup(rm, 23, &r) != INVALID_ADDRESS) {
        msg = "remove 2 - lookup 1";
        goto fail;
    }

    /* pass */
    v = rangemap_lookup(rm, 20, &r);
    if (v != (void *)3 ||
        r.start != 20 ||
        r.end != 21) {
        msg = "remove 2 - lookup 2";
        goto fail;
    }

    v = rangemap_lookup(rm, 24, &r);
    if (v != (void *)3 ||
        r.start != 24 ||
        r.end != 25) {
        msg = "remove 2 - lookup 3";
        goto fail;
    }
#endif

    /* range lookup */
    rmnode_handler rh = stack_closure(basic_test_validate);
    rangemap_range_lookup(rm, irange(0, 26), rh);
    return true;

  fail:
    deallocate_rangemap(rm);
    msg_err("rangemap basic test failed: %s\n", msg);
    return false;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
        goto fail;

    /*
      if (!random_test(h, 100, 1000))
      goto fail;
    */

    msg_debug("range test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("range test failed\n");
    exit(EXIT_FAILURE);
}
