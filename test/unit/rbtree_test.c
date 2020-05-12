#include <runtime.h>
#include <stdlib.h>

//#define RBTEST_DEBUG
#ifdef RBTEST_DEBUG
#define rbtest_debug(x, ...) do {rprintf("RBTEST %s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define rbtest_debug(x, ...)
#endif

typedef struct testnode {
    struct rbnode node;
    int key;
} *testnode;

closure_function(0, 2, int, test_compare,
                 rbnode, a, rbnode, b)
{
    testnode ta = (testnode)a, tb = (testnode)b;
    return ta->key < tb->key ? -1 : (ta->key > tb->key ? 1 : 0);
}

closure_function(0, 1, boolean, dump_node,
                 rbnode, n)
{
    testnode tn = (testnode)n;
    rprintf(" %d", tn->key);
    return true;
}

void test_dump(rbtree t)
{
    rprintf("tree %p, preorder:\n", t);
    rbtree_dump(t, RB_PREORDER);
    rprintf("in order:\n");
    rbtree_traverse(t, RB_INORDER, stack_closure(dump_node));
    rprintf("\n");
}

closure_function(3, 1, boolean, test_max_lte_node,
                 rbtree, t, rbnode *, last, boolean *, result,
                 rbnode, n)
{
    testnode tn = (testnode)n;
    if (tn->key > 0) {
        struct testnode k;
        k.key = tn->key - 1;
        rbnode ml = rbtree_lookup_max_lte(bound(t), &k.node);
        rbnode x = *bound(last) ? *bound(last) : INVALID_ADDRESS;
        if (ml != x) {
            rprintf("%s: lookup max lte returned %p, should be last (%p)\n",
                    __func__, ml, x);
            *bound(result) = false;
            return false;
        }
    }
    *bound(last) = n;
    return true;
}

static boolean test_max_lte(rbtree t)
{
    rbnode last = 0;
    boolean result = true;
    rbtree_traverse(t, RB_INORDER, stack_closure(test_max_lte_node, t, &last, &result));
    if (last) {
        struct testnode k;
        k.key = ((testnode)last)->key + 1;
        rbnode ml = rbtree_lookup_max_lte(t, &k.node);
        if (ml != last) {
            rprintf("%s: lookup max lte for key %d after last node "
                    "returned %p instead of last (%p)\n", __func__,
                    k.key, ml, last);
            return false;
        }
    }
    return result;
}

static boolean test_insert(heap h, rbtree t, int key, boolean validate)
{
    testnode tn = allocate(h, sizeof(struct testnode));
    if (tn == INVALID_ADDRESS)
        return false;
    tn->key = key;
    init_rbnode(&tn->node);
    rbtest_debug("inserting node %p, key %d\n", &tn->node, key);
    boolean r = rbtree_insert_node(t, &tn->node);
    if (validate) {
        status s = rbtree_validate(t);
        if (!is_ok(s)) {
            rprintf("%s: rbtree_validate failed with %v ", __func__, s);
            goto out_fail;
        }
        rbnode r = rbtree_lookup(t, &tn->node);
        if (r != &tn->node) {
            rprintf("%s: rbtree_lookup failed (returned %p) ", __func__, r);
            goto out_fail;
        }
        if (!test_max_lte(t)) {
            rprintf("%s: max lte test failed ", __func__);
            goto out_fail;
        }
    }
    return r;
  out_fail:
    rprintf("after inserting node %p (key %d)\n", &tn->node, key);
    return false;
}

static boolean test_remove(heap h, rbtree t, int key, boolean expect)
{
    struct testnode tk;
    tk.key = key;
    rbtest_debug("deleting by key %d\n", key);
    boolean result = rbtree_remove_by_key(t, &tk.node);
    if (result != expect) {
        msg_err("delete failed (result %d)\n", result);
        return false;
    }
#ifdef RBTEST_DEBUG
    test_dump(t);
#endif
    status s = rbtree_validate(t);
    if (!is_ok(s)) {
        msg_err("validate failed: %v\n", s);
        return false;
    }
    rbtest_debug("lookup:\n");
    rbnode r = rbtree_lookup(t, &tk.node);
    if (r != INVALID_ADDRESS) {
        msg_err("lookup for key %d should have failed (returned %p, key %d)\n",
                key, r, ((testnode)r)->key);
        return false;
    }
    return true;
}

closure_function(1, 1, boolean, dealloc_testnode,
                 heap, h,
                 rbnode, n)
{
    deallocate(bound(h), n, sizeof(struct testnode));
    return true;
}

closure_function(1, 1, boolean, assert_no_node,
                 boolean *, result,
                 rbnode, n)
{
    *bound(result) = false;
    return false;
}

/* TODO: add test vectors to cover each tree transformation */
#define N_INSERT_NODES 12
static int insert_keys[][N_INSERT_NODES] = {
    { 1, -1 },
    { 1, 2, -1 },
    { 1, 2, 3, -1 },
    { 1, 2, 3, 4, -1 },
    { 1, 2, 3, 4, 5, -1 },
    { 1, 2, 3, 4, 5, 6, -1 },
    { 1, 2, 3, 4, 5, 6, 7, -1 },
    { 1, 2, 3, 4, 5, 6, 7, 8, -1 },
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, -1 },
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1 },
    { 3, 2, 1, -1 },
    { -1 },
};

static int insert_preorder[][N_INSERT_NODES] = {
    { 1, -1 },
    { 2, 1, -1 },               /* rotate to make left leaning */
    { 2, 1, 3, -1 },            /* break up 4-node */
    { 2, 1, 4, 3, -1 },
    { 4, 2, 1, 3, 5, -1 },
    { 4, 2, 1, 3, 6, 5, -1 },
    { 4, 2, 1, 3, 6, 5, 7, -1 },
    { 4, 2, 1, 3, 6, 5, 8, 7, -1 },
    { 4, 2, 1, 3, 8, 6, 5, 7, 9, -1 },
    { 4, 2, 1, 3, 8, 6, 5, 7, 10, 9, -1 },
    { 2, 1, 3, -1 },            /* break up consecutive reds */
};

static int remove_keys[][N_INSERT_NODES] = {
    { 1, -1 },
    { 1, -1 },
    { 1, -1 },
    { 4, -1 },
    { 5, -1 },
    { 1, -1 },
    { 3, 4, -1 },
    { 4, -1 },
    { 9, -1 },
    { 2, -1 },
    { 3, 2, 1, -1 },
    { -1 },
};

/* consecutive red fixup remaining? */
static int remove_preorder[][N_INSERT_NODES] = {
    { -1 },
    { 2, -1 },
    { 3, 2, -1 },               /* check_move_red left: color flip */
    { 2, 1, 3, -1 },            /* left is red, rotate right */
    { 2, 1, 4, 3, -1 },         /* right rotate, check red right color flip */
    { 4, 3, 2, 6, 5, -1 },      /* lh color flip and make left leaning */
    { 6, 2, 1, 5, 7, -1 },      /* color flip, other left red */
    { 5, 2, 1, 3, 7, 6, 8, -1}, /* same, plus left hand, rotate right, break up 4-node */
    { 4, 2, 1, 3, 6, 5, 8, 7, -1}, /* left is red, rotate right */
    { 6, 4, 3, 1, 5, 8, 7, 10, 9, -1},
    { -1 },
};

closure_function(3, 1, boolean, validate_preorder_vec,
                 int *, vec, int *, index, boolean *, match,
                 rbnode, n)
{
    testnode tn = (testnode)n;
    int i = *bound(index);
    int *p = bound(vec) + i;
    rbtest_debug("index %d, expect %d, tn->key %d\n", i, *p, tn->key);
    if (*p == -1) {
        rprintf("%s: result vec exceeded at index %d\n", __func__, i);
        *bound(match) = false;
        return false;
    }
    if (*p != tn->key) {
        rprintf("%s: key %d at index %d, expected %d\n", __func__, tn->key, i, *p);
        *bound(match) = false;
        return false;
    }
    *bound(index) = i + 1;
    return true;
}

static boolean do_transformation_test(rbtree t, heap h, int i, boolean insert)
{
    int index, k;
    boolean match;
    char *op = insert ? "insertion" : "removal";
    int *keys = insert ? insert_keys[i] : remove_keys[i];

    if (keys[0] == -1)
        return true;

    rbtest_debug("%s test %d:\n", op, i);
    for (int j = 0; j < N_INSERT_NODES && (k = keys[j]) != -1; j++) {
        rbtest_debug("   %d: %d\n", j, k);
        boolean result = insert ? test_insert(h, t, k, true) : test_remove(h, t, k, true);
        if (!result) {
            rprintf("%s: %s failed for test %d, idx %d, key %d\n", __func__, op, i, j, k);
            return false;   /* XXX leak */
        }
    }
#ifdef RBTEST_DEBUG
    rbtree_dump(t, RB_PREORDER);
#endif
    rbtest_debug("validate %ss:\n", op);
    index = 0;
    match = true;
    int *rvec = insert ? insert_preorder[i] : remove_preorder[i];
    rbtree_traverse(t, RB_PREORDER,
                    stack_closure(validate_preorder_vec, rvec, &index, &match));
    if (match) {
        if (rvec[index] != -1) {
            rprintf("%s: in-order traversal for %s test %d gave incomplete results, end index %d\n",
                    __func__, op, i, index);
            return false;
        }
    }
    if (!match) {
        rprintf("%s: validate for %s test %d failed\n", __func__, op, i);
        return false;
    }
    rbtest_debug("passed\n\n");
    return true;
}

static boolean transformation_tests(heap h)
{
    for (int i = 0; insert_keys[i][0] != -1; i++) {
        struct rbtree t;
        init_rbtree(&t, stack_closure(test_compare), stack_closure(dump_node));

        if (!do_transformation_test(&t, h, i, true))
            return false;

        if (!do_transformation_test(&t, h, i, false))
            return false;

        /* dealloc remaining nodes */
        destruct_rbtree(&t, stack_closure(dealloc_testnode, h));
    }
    return true;
}

/* braindead test */
static boolean basic_test(heap h)
{
    rbtree t = allocate_rbtree(h, closure(h, test_compare), closure(h, dump_node));
    if (t == INVALID_ADDRESS) {
        msg_err("allocate_rbtree() failed\n");
        return false;
    }

    rbtest_debug("insert 0 - 99\n");
    for (int i = 0; i < 100; i++) {
        if (!test_insert(h, t, i, true))
            return false;
    }

    rbtest_debug("insert 199 - 100\n");
    for (int i = 199; i >= 100; i--) {
        if (!test_insert(h, t, i, true))
            return false;
    }

    rbtest_debug("attempt to insert duplicates\n");
    for (int i = 0; i < 200; i++) {
        if (test_insert(h, t, i, false)) {
            msg_err("insert should have failed\n");
            return false;
        }
    }

    rbtest_debug("remove all nodes\n");
    for (int i = 0; i < 200; i++) {
        if (!test_remove(h, t, i, true))
            return false;
    }

    destruct_rbtree(t, stack_closure(dealloc_testnode, h));
    status s = rbtree_validate(t);
    if (!is_ok(s)) {
        rprintf("validate failed after tree destruct: %v\n", s);
        return false;
    }
    boolean result = true;
    deallocate_rbtree(t, stack_closure(assert_no_node, &result));
    return result;
}

#define RANDOM_VEC_ORDER 14
#define RANDOM_VECLEN    U64_FROM_BIT(RANDOM_VEC_ORDER)

static boolean random_test(heap h)
{
    int vec[RANDOM_VECLEN];
    rbtree t = allocate_rbtree(h, closure(h, test_compare), closure(h, dump_node));
    assert(rbtree_get_count(t) == 0);
    if (t == INVALID_ADDRESS) {
        msg_err("allocate_rbtree() failed\n");
        return false;
    }

    for (int i = 0; i < RANDOM_VECLEN; i++) {
        boolean r;
      redo:
        /* restrict range so as to induce collisions */
        vec[i] = random_u64() & MASK(RANDOM_VEC_ORDER + 1);
        r = test_insert(h, t, vec[i], false);
        if (!r) {
            struct testnode tn;
            tn.key = vec[i];
            rbnode rn = rbtree_lookup(t, &tn.node);
            if (rn == INVALID_ADDRESS) {
                msg_err("both insert and lookup failed\n");
                return false;
            }
            if (((testnode)rn)->key != vec[i]) {
                msg_err("found node key mismatch\n");
                return false;
            }
            goto redo;
        }
    }
    assert(rbtree_get_count(t) == RANDOM_VECLEN);

    for (int i = 0; i < RANDOM_VECLEN; i++) {
        test_remove(h, t, vec[i], true);
    }
    assert(rbtree_get_count(t) == 0);

    destruct_rbtree(t, stack_closure(dealloc_testnode, h));
    status s = rbtree_validate(t);
    if (!is_ok(s)) {
        rprintf("validate failed after tree destruct: %v\n", s);
        return false;
    }
    boolean result = true;
    deallocate_rbtree(t, stack_closure(assert_no_node, &result));
    return result;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
        goto fail;

    if (!transformation_tests(h))
        goto fail;

    if (!random_test(h))
        goto fail;

    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("test failed\n");
    exit(EXIT_FAILURE);
}
