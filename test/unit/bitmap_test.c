#include <runtime.h>
#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define WHOLE_RANGE irange(0, infinity)


/**
 * Inspired by id_alloc_from_range in id.c
 * Returns a bitmap to further test on.
 */
u64 test_alloc(heap meta, heap map, u64 length) {
    bitmap b = allocate_bitmap(meta, map, length);
    if (b == INVALID_ADDRESS) {
        msg_err("!!! allocation failed for bitmap");
        return false;
    }
    return true;
}

boolean basic_test(heap h)
{
    if(!test_alloc(h, h, infinity))
        return false;
    return true;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    if (!basic_test(h)) 
        goto fail;

    rprintf("tests passing so far\n");
    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
    fail:
        msg_err("test failed\n");
        exit(EXIT_FAILURE);
}



