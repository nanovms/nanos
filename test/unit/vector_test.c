/* XXX TODO
   - test split()
   - test join()
   - test (or just delete; it's unused) bitvector_set()
   - test build_vector_internal()
*/

//#define ENABLE_MSG_DEBUG
#include <runtime.h>
#include <stdio.h>
#include <stdlib.h>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

boolean basic_test(heap h)
{
    char * msg = "";
    vector v = allocate_vector(h, 10);

    /* null vec test */
    if (vector_pop(v) ||
        vector_peek(v) ||
        vector_delete(v, 0)) {
        msg = "null vector pop / peek / delete fail";
        goto fail;
    }

    /* stack op test */
    vector_push(v, (void *)100);
    if (vector_peek(v) != (void *)100 ||
        vector_pop(v) != (void *)100 ||
        vector_peek(v) != (void *)0 ||
        vector_pop(v) != (void *)0) {
        msg = "single peek or pop fail";
        goto fail;
    }

    vector_push(v, (void *)100);
    vector_push(v, (void *)200);
    vector_push(v, (void *)300);
    if (vector_peek(v) != (void *)300 ||
        vector_pop(v) != (void *)300 ||
        vector_peek(v) != (void *)200 ||
        vector_pop(v) != (void *)200 ||
        vector_peek(v) != (void *)100 ||
        vector_pop(v) != (void *)100 ||
        vector_peek(v) != (void *)0 ||
        vector_pop(v) != (void *)0) {
        msg = "double peek or pop fail";
        goto fail;
    }

    /* resize test */
    deallocate_vector(v);
    v = allocate_vector(h, 1);
    int n = 1 << 20;
    for (long i = 0; i < n; i++) {
        void * prev = v->contents;
        vector_set(v, i, (void *)i);
        if (vector_length(v) != i + 1) {
            msg = "resize: wrong vector length";
            goto fail;
        }

        /* Attempt to detect resize and check content */
        if (prev != v->contents || i == n - 1) {
            msg_debug("resize detected at index %ld\n", i);
            for (long j = 0; j < i + 1; j++) {
                if (vector_get(v, j) != (void *)j) {
                    msg = "resize: content mismatch";
                    goto fail;
                }
            }
        }
    }

    /* foreach - assuming it's meant to always be in order */
    long i = 0;
    void *x;
    vector_foreach(v, x) {
        if ((long)x != i) {
            msg = "foreach: content mismatch";
            goto fail;
        }
        i++;
    }

    if (i != n) {
        msg = "foreach: iterations doesn't match length";
        goto fail;
    }

    if (vector_get(v, -1) || vector_get(v, n)) {
        msg = "get: out of bounds access";
        goto fail;
    }

    for (i = 0; i < 8; i++) {
        if ((long)vector_delete(v, 0) != i) {
            msg = "delete: content mismatch";
            goto fail;
        }
    }
    for (i = 10; i < 20; i++) {
        if ((long)vector_delete(v, 2) != i) {
            msg = "delete: content mismatch";
            goto fail;
        }
    }
    if (vector_length(v) != n - 8 - 10) {
        msg = "delete: wrong vector length";
        goto fail;
    }

    if ((vector_delete_range(v, n - 20, n) != 2) ||
        (vector_delete_range(v, n - 10, n) != 0))  {
        msg = "delete_range: wrong result";
        goto fail;
    }
    if (vector_length(v) != n - 20) {
        msg = "delete_range: wrong vector length";
        goto fail;
    }
    if ((long)vector_get(v, n - 21) != (n - 3)) {
        msg = "delete_range: content mismatch";
        goto fail;
    }

    deallocate_vector(v);
    v = allocate_vector(h, 1);
    vector_foreach(v, x) {
        msg = "foreach: body run on zero len";
        goto fail;
    }

    deallocate_vector(v);
    return true;
  fail:
    deallocate_vector(v);
    printf("vector basic test failed: %s\n", msg);
    return false;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
	goto fail;

    msg_debug("vector test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("vector test failed\n");
    exit(EXIT_FAILURE);
}
