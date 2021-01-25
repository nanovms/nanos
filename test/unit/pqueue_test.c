//#define ENABLE_MSG_DEBUG
#include <runtime.h>
#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

struct pqueue_test_elem {
    int val;
};

boolean basic_sort(void * a, void * b)
{
    return (u64)a < (u64)b;
}

boolean peek_check(pqueue q, u64 v)
{
    void * rv = pqueue_peek(q);
    msg_debug("peek_check: want %ld, got %ld\n", v, (u64)rv);
    return rv == (void *)v;
}

boolean pop_check(pqueue q, u64 v)
{
    void * rv = pqueue_pop(q);
    msg_debug("pop_check: want %ld, got %ld\n", v, (u64)rv);
    return rv == (void *)v;
}

boolean peek_pop_check(pqueue q, u64 v)
{
    return peek_check(q, v) && pop_check(q, v) ? true : false;
}

boolean basic_test(heap h)
{
    char * msg = "";
    pqueue q = allocate_pqueue(h, basic_sort);

    /* Single entry */
    pqueue_insert(q, (void *)500);
    if (!peek_pop_check(q, 500)) {
        msg = "insert fail 0";
        goto fail;
    }

    if (peek_check(q, 500)) {
        msg = "insert fail 1";
        goto fail;
    }

    if (pop_check(q, 500)) {
        msg = "insert fail 2";
        goto fail;
    }

    /* Duplicate */
    pqueue_insert(q, (void *)500);
    pqueue_insert(q, (void *)500);
    if (!peek_pop_check(q, 500)) {
        msg = "double 0";
        goto fail;
    }

    if (!peek_pop_check(q, 500)) {
        msg = "double 1";
        goto fail;
    }

    if (peek_check(q, 500)) {
        msg = "double 2";
        goto fail;
    }

    if (pop_check(q, 500)) {
        msg = "double 3";
        goto fail;
    }

    /* Left hand */
    pqueue_insert(q, (void *)500);
    pqueue_insert(q, (void *)400);
    if (!peek_pop_check(q, 500)) {
        msg = "left hand 0";
        goto fail;
    }
    if (!peek_pop_check(q, 400)) {
        msg = "left hand 1";
        goto fail;
    }

    /* Right hand */
    pqueue_insert(q, (void *)400);
    pqueue_insert(q, (void *)500);
    if (!peek_pop_check(q, 500)) {
        msg = "right hand 0";
        goto fail;
    }
    if (!peek_pop_check(q, 400)) {
        msg = "right hand 1";
        goto fail;
    }

    /* Three ascending (two swap) */
    pqueue_insert(q, (void *)300);
    pqueue_insert(q, (void *)400);
    pqueue_insert(q, (void *)500);
    if (!peek_pop_check(q, 500) ||
        !peek_pop_check(q, 400) ||
        !peek_pop_check(q, 300)) {
        msg = "three ascending";
        goto fail;
    }
    
    /* Three descending (no swap) */
    pqueue_insert(q, (void *)500);
    pqueue_insert(q, (void *)400);
    pqueue_insert(q, (void *)300);
    if (!peek_pop_check(q, 500) ||
        !peek_pop_check(q, 400) ||
        !peek_pop_check(q, 300)) {
        msg = "three ascending";
        goto fail;
    }
    
    return true;
  fail:
    deallocate_pqueue(q);
    msg_err("pqueue basic test failed: %s\n", msg);
    return false;
}

/* TODO more thorough would be to track insertions in a list or some
   other structure and parity check */
boolean random_test(heap h, int n, int passes)
{
    pqueue q = allocate_pqueue(h, basic_sort);
    char * msg = "";
    int remain = 0;

    for (int pass = 0; pass < passes; pass++) {
        msg_debug("random_test pass %d\n", pass);
        for (int i = remain; i < n; i++) {
            u64 r = random_u64();
            msg_debug("  insert %d\n", r);
            pqueue_insert(q, (void *)r);
        }
        u64 last = infinity;
        u64 npop = (pass == passes - 1) ? n : n / 2;
        remain = n - npop;
        for (int i = 0; i < npop; i++) {
            u64 v = (u64)pqueue_pop(q);
            msg_debug("  pop %ld\n", v);
            if (v > last) {
                msg = "pop out of order";
                goto fail;
            }
            last = v;
        }
    }
    if (pqueue_pop(q) != INVALID_ADDRESS) {
        msg = "queue should be empty but isn't";
        goto fail;
    }
    return true;
  fail:
    msg_err("random_test fail; %s\n", msg);
    deallocate_pqueue(q);
    return false;
}

static boolean reorder_sort(void *a, void *b)
{
    return (((struct pqueue_test_elem *)a)->val < ((struct pqueue_test_elem *)b)->val);
}

static boolean reorder_test(heap h, int passes)
{
    const int max_elems = 512;
    struct pqueue_test_elem elems[max_elems];
    int num_elems;
    int val;
    char *err_msg = NULL;

    pqueue q = allocate_pqueue(h, reorder_sort);
    for (int pass = 0; pass < passes; pass++) {
        num_elems = (rand() % max_elems) + 1;
        for (int i = 0; i < num_elems; i++)
            pqueue_insert(q, &elems[i]);
        for (int i = 0; i < num_elems; i++)
            elems[i].val = rand();
        pqueue_reorder(q);
        val = RAND_MAX;
        for (int i = 0; i < num_elems; i++) {
            struct pqueue_test_elem *elem = pqueue_pop(q);

            if (elem->val > val) {
                err_msg = "pop out of order";
                goto done;
            }
            val = elem->val;
        }
        if (pqueue_pop(q) != INVALID_ADDRESS) {
            err_msg = "popped one too many elements";
            goto done;
        }
    }
  done:
    deallocate_pqueue(q);
    if (!err_msg)
        return true;
    msg_err("%s\n", err_msg);
    return false;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
	goto fail;

    if (!random_test(h, 100, 1000))
        goto fail;

    if (!reorder_test(h, 1000))
        goto fail;

    msg_debug("pqueue test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("pqueue test failed\n");
    exit(EXIT_FAILURE);
}
