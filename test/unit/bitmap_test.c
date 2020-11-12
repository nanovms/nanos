#include <runtime.h>
#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define WHOLE_RANGE irange(0, infinity)


/**
 *  Tests allocation of bitmap using allocate_bitmap 
 *  function.
 */
bitmap test_alloc() {
    heap h = init_process_runtime();
    bitmap b = allocate_bitmap(h, h, infinity);
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

/**
 *  Tests copying of bitmap using bitmap_copy
 *  function.
 */ 
boolean test_copy(bitmap b) {
    heap h = init_process_runtime();
    bitmap b_cpy = allocate_bitmap(h, h, infinity);
    bitmap_copy(b, b_cpy);
    if (b_cpy == NULL) { // TODO
        msg_err("!!! copying failed for bitmap\n");
        return false;
    }
    return true;
}

boolean basic_test()
{
    // tests bitmap allocate
    bitmap b = test_alloc();
    if (b == INVALID_ADDRESS) return false;
    
    // tests bitmap clone
    if (!test_clone(b)) return false;

    // tests bitmap copy
    if (!test_copy(b)) return false;
    
    // deallocates bitmap
    deallocate_bitmap(b);
    return true;
}

int main(int argc, char **argv)
{
    if (!basic_test()) 
        goto fail;

    rprintf("tests passing so far\n");
    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
    fail:
        msg_err("test failed\n");
        exit(EXIT_FAILURE);
}



