#include <runtime.h>
#include <stdlib.h>

boolean basic_sort(void * a, void * b)
{
    return (u64)a < (u64)b;
}

boolean peek_check(pqueue pq, u64 v)
{
    void * rv;
    if ((rv = pqueue_peek(pq)) != (void *)v)
        return false;
    return true;
}

boolean pop_check(pqueue pq, u64 v)
{
    void * rv;
    if ((rv = pqueue_pop(pq)) != (void *)v)
        return false;
    return true;
}

boolean peek_pop_check(pqueue pq, u64 v)
{
    return peek_check(pq, v) && pop_check(pq, v) ? true : false;
}

boolean basic_test(heap h)
{
    char * msg = "";
    pqueue pq = allocate_pqueue(h, basic_sort);

    /* Single entry */
    pqueue_insert(pq, (void *)500);
    if (!peek_pop_check(pq, 500)) {
        msg = "insert fail 0";
        goto fail;
    }

    if (peek_check(pq, 500)) {
        msg = "insert fail 1";
        goto fail;
    }

    if (pop_check(pq, 500)) {
        msg = "insert fail 2";
        goto fail;
    }

    /* Duplicate */
    pqueue_insert(pq, (void *)500);
    pqueue_insert(pq, (void *)500);
    if (!peek_pop_check(pq, 500)) {
        msg = "double 0";
        goto fail;
    }

    if (!peek_pop_check(pq, 500)) {
        msg = "double 1";
        goto fail;
    }

    if (peek_check(pq, 500)) {
        msg = "double 2";
        goto fail;
    }

    if (pop_check(pq, 500)) {
        msg = "double 3";
        goto fail;
    }

    /* Left hand */
    pqueue_insert(pq, (void *)500);
    pqueue_insert(pq, (void *)400);
    if (!peek_pop_check(pq, 500)) {
        msg = "left hand 0";
        goto fail;
    }
    if (!peek_pop_check(pq, 400)) {
        msg = "left hand 1";
        goto fail;
    }

    /* Right hand */
    pqueue_insert(pq, (void *)400);
    pqueue_insert(pq, (void *)500);
    if (!peek_pop_check(pq, 500)) {
        msg = "right hand 0";
        goto fail;
    }
    if (!peek_pop_check(pq, 400)) {
        msg = "right hand 1";
        goto fail;
    }

    return true;
  fail:
    // XXX no dealloc implemented
    msg_err("pqueue basic test failed: %s\n", msg);
    return false;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
	goto fail;

    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("test failed\n");
    exit(EXIT_FAILURE);
}
