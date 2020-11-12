#include <runtime.h>
#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define WHOLE_RANGE irange(0, infinity)


/**
 *  Tests allocation of bitmap using allocate_bitmap 
 *  function.
 */
bitmap test_alloc(heap meta, heap map, u64 length) {
    bitmap b = allocate_bitmap(meta, map, length);
    if (b == INVALID_ADDRESS) 
        msg_err("!!! allocation failed for bitmap\n");
    return b;
}

/**
 *  Tests cloning of bitmap using bitmap_clone 
 *  function.
 */  
boolean test_clone(bitmap b) {
    bitmap b_cpy = bitmap_clone(b);
    if (b_cpy == INVALID_ADDRESS) {
        msg_err("!!! cloning failed for bitmap\n");
        return false;
    }
    return true;
}

boolean basic_test(heap h)
{
    // tests bitmap allocate
    bitmap b = test_alloc(h, h, infinity);
    if (b == INVALID_ADDRESS) return false;
    
    // tests bitmap clone
    if (!test_clone(b)) return false;
    
    // deallocates bitmap
    deallocate_bitmap(b);
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



