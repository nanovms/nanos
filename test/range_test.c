/* This test is only suitable for the sorted list implementation. It
   will need doctoring if the behavior of range search, etc., changes. */

//#define ENABLE_MSG_DEBUG
#include <runtime.h>
#include <stdlib.h>

struct rm_result {
    range r;
    void * val;
};

static struct rm_result rm_results[] = {
    { irange(0, 15), range_hole },
    { irange(15, 20), (void *) 1 },
    { irange(20, 21), (void *) 3 },
    { irange(21, 24), range_hole },
    { irange(24, 25), (void *) 3 },
    { irange(25, 26), range_hole } };

static CLOSURE_0_2(basic_test_validate, void, range, void *);
static void basic_test_validate(range r, void * val)
{
    static int count = 0;
    int nresults = sizeof(rm_results) / sizeof(struct rm_result);
    if (count >= nresults) {
        msg_err("range lookup extraneous result: %R, %p\n", r, val);
        exit(EXIT_FAILURE);
    }
    if (!range_equal(r, rm_results[count].r) || val != rm_results[count].val) {
        msg_err("range lookup result mismatch, expected %R, %p but got %R, %p\n",
                rm_results[count].r, rm_results[count].val, r, val);
        exit(EXIT_FAILURE);
    }
    count++;
}

boolean basic_test(heap h)
{
    char * msg = "";
    rangemap rm = allocate_rangemap(h);
    if (rm == INVALID_ADDRESS) {
        msg_err("failed to allocate rangemap\n");
        return false;
    }

    boolean rv;
    rv = rangemap_insert(rm, 10, 10, (void *)1);
    if (!rv) {
        msg = "insert 0";
        goto fail;
    }

    /* should fail, overlap of one */
    rv = rangemap_insert(rm, 19, 1, (void *)2);
    if (rv) {
        msg = "insert 1";
        goto fail;
    }

    /* should pass, abut first range */
    rv = rangemap_insert(rm, 20, 10, (void *)3);
    if (!rv) {
        msg = "insert 2";
        goto fail;
    }

    /* basic lookup (pass) */
    void * v;
    range r;
    v = rangemap_lookup(rm, 19, &r);
    if (v != (void *)1 ||
        r.start != 10 ||
        r.end != 20) {
        msg = "lookup 0";
        goto fail;
    }

    /* lookup in hole (fail) */
    v = rangemap_lookup(rm, 9, &r);
    if (v) {
        msg = "lookup 1";
        goto fail;
    }

    /* lookup next range (pass) */
    v = rangemap_lookup(rm, 20, &r);
    if (v != (void *)3 ||
        r.start != 20 ||
        r.end != 30) {
        msg = "lookup 2";
        goto fail;
    }

    /* test partial delete (head trim) */
    rv = rangemap_remove(rm, 5, 10);
    if (!rv) {
        msg = "remove 0 - no match";
        goto fail;
    }

    /* should fail */
    v = rangemap_lookup(rm, 14, &r);
    if (v) {
        msg = "remove 0 - lookup 0";
        goto fail;
    }

    /* pass */
    v = rangemap_lookup(rm, 15, &r);
    if (v != (void *)1 ||
        r.start != 15 ||
        r.end != 20) {
        msg = "remove 0 - lookup 1";
        goto fail;
    }

    /* test partial delete (tail trim) */
    rv = rangemap_remove(rm, 25, 6);
    if (!rv) {
        msg = "remove 1 - no match";
        goto fail;
    }

    /* should fail */
    v = rangemap_lookup(rm, 25, &r);
    if (v) {
        msg = "remove 1 - lookup 0";
        goto fail;
    }

    v = rangemap_lookup(rm, 29, &r);
    if (v) {
        msg = "remove 1 - lookup 1";
        goto fail;
    }

    /* pass */
    v = rangemap_lookup(rm, 24, &r);
    if (v != (void *)3 ||
        r.start != 20 ||
        r.end != 25) {
        msg = "remove 1 - lookup 2";
        goto fail;
    }

    /* test partial delete (hole trim) */
    rv = rangemap_remove(rm, 21, 3);
    if (!rv) {
        msg = "remove 2 - no match";
        goto fail;
    }

    /* should fail */
    v = rangemap_lookup(rm, 21, &r);
    if (v) {
        msg = "remove 2 - lookup 0";
        goto fail;
    }

    v = rangemap_lookup(rm, 23, &r);
    if (v) {
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

    /* range lookup */
    subrange sr = closure(h, basic_test_validate);
    rangemap_range_lookup(rm, irange(0, 26), sr);
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
