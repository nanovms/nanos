#include <runtime.h>
#include <stdlib.h>

boolean basic_test(heap h)
{
    char * msg = "";
    vector v = allocate_vector(h, 10);

    /* null vec test */
    if (vector_pop(v) ||
        vector_peek(v)) {
        msg = "null vector pop / peek fail";
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
    return true;
  fail:
    deallocate_vector(v);
    msg_err("vector basic test failed: %s\n", msg);
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
