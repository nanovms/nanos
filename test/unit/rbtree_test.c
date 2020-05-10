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
    int value;
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

closure_function(1, 1, boolean, test_inorder_node,
                 rbnode *, last,
                 rbnode, n)
{
//    rprintf("-> %d (%p)\n", ((testnode)n)->key, n);
    if (*bound(last) != 0) {
        rbnode last = *bound(last);
        rbnode prev = rbnode_get_prev(n);
        if (prev != last) {
            msg_err("prev of n %p doesn't match last %p\n", prev, last);
            return false;
        }
        rbnode next = rbnode_get_next(last);
        if (next != n) {
            msg_err("next of last %p doesn't match node %p\n", next, n);
            return false;
        }
    } else {
        rbnode prev = rbnode_get_prev(n);
        if (prev != INVALID_ADDRESS) {
            msg_err("first element %p, prev %p, should be invalid\n", n, prev);
            return false;
        }
    }
    *bound(last) = n;
    return true;
}

static boolean test_inorder(rbtree t)
{
    if (!t->root)
        return true;
    rbnode last = 0;
    boolean r = rbtree_traverse(t, RB_INORDER, stack_closure(test_inorder_node, &last));
    if (!r)
        return false;
    if (rbnode_get_next(last) != INVALID_ADDRESS) {
        msg_err("next of last element should be invalid\n");
        return false;
    }
    return true;
}

static boolean test_insert(heap h, rbtree t, int key, int value, boolean validate)
{
    testnode tn = allocate(h, sizeof(struct testnode));
    if (tn == INVALID_ADDRESS)
        return false;
    tn->key = key;
    tn->value = value;
    init_rbnode(&tn->node);
    rbtest_debug("inserting node %p, key %d\n", &tn->node, key);
    boolean r = rbtree_insert_node(t, &tn->node);
    if (validate) {
        if (!rbtree_validate(t)) {
            msg_err("validate failed after inserting node %p (key %d)\n", &tn->node, key);
            return false;
        }
        rbnode r = rbtree_lookup(t, &tn->node);
        if (r != &tn->node) {
            msg_err("lookup returned %p for node %p (key %d)\n", r, &tn->node, key);
            return false;
        }
        if (!test_inorder(t)) {
            msg_err("inorder test failed after inserting node %p (key %d)\n", &tn->node, key);
            return false;
        }
    }
    return r;
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
    if (!rbtree_validate(t)) {
        msg_err("validate failed\n");
        return false;
    }
    rbtest_debug("lookup:\n");
    rbnode r = rbtree_lookup(t, &tk.node);
    if (r != INVALID_ADDRESS) {
        msg_err("lookup for key %d should have failed (returned %p, key %d)\n",
                key, r, ((testnode)r)->key);
        return false;
    }
    rbtest_debug("test inorder:\n");
    if (!test_inorder(t)) {
        msg_err("inorder test failed after deleting key %d\n", key);
        return false;
    }
    return true;
}

#if 0
static testnode test_lookup(rbtree t, int key)
{


}
#endif

static boolean basic_test(heap h)
{
    rbtree t = allocate_rbtree(h, closure(h, test_compare), closure(h, dump_node));
    if (t == INVALID_ADDRESS) {
        msg_err("allocate_rbtree() failed\n");
        return false;
    }
#if 0
    int insertion_keys[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1 };
    int k;
    for (int i = 0; (k = insertion_keys[i]) != -1; i++) {
        if (!test_insert(h, t, k, k))
            return false;
    }

    if (!test_remove(h, t, 11, false))
        return false;

    for (int i = 0; (k = insertion_keys[i]) != -1; i++) {
        if (!test_remove(h, t, k, true))
            return false;
    }
#endif

#if 1
    for (int i = 0; i < 100; i++) {
        if (!test_insert(h, t, i, i, true))
            return false;
    }
#if 1
    for (int i = 199; i >= 100; i--) {
        if (!test_insert(h, t, i, i, true))
            return false;
    }
    for (int i = 0; i < 200; i++) {
        if (test_insert(h, t, i, i, true)) {
            msg_err("insert should have failed\n");
            return false;
        }
    }
#endif
    for (int i = 199; i >= 0; i--) {
        if (!test_remove(h, t, i, true))
            return false;
    }
#endif

    // destruct
    return true;
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
        vec[i] = random_u64() & MASK(RANDOM_VEC_ORDER); // XXX prob add some
        r = test_insert(h, t, vec[i], vec[i], false);
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

//    test_dump(t);

    for (int i = 0; i < RANDOM_VECLEN; i++) {
        test_remove(h, t, vec[i], true);
    }
    assert(rbtree_get_count(t) == 0);

    return true;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (0 && !basic_test(h))
        goto fail;

    if (!random_test(h))
        goto fail;

    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("test failed\n");
    exit(EXIT_FAILURE);
}
