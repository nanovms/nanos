#include <unix_process_runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>

#define msg_err(fmt, ...) rprintf("%s error: " fmt, __func__, \
				  ##__VA_ARGS__);

#if 1
#define msg_debug(fmt, ...) rprintf("%s debug: " fmt, __func__, \
				    ##__VA_ARGS__);
#else
#define msg_debug(fmt, ...)
#endif

boolean objcache_test(heap meta, heap parent)
{
    /* just a cursory test */
    int n = 1024;
    int size = 32;
    int opp = PAGESIZE / size;
    int i;
    heap h = allocate_objcache(meta, parent, size);
    vector objs = allocate_vector(meta, n);

    msg_debug("objs %p, heap %p\n", objs, h);
    
    if (h == INVALID_ADDRESS) {
	msg_err("tb: failed to allocate objcache heap\n");
	/* XXX free vector */
	return false;
    }

    /* allocate a page's worth */
    i = opp - 1;
    do {
	void * p = allocate(h, size);
	if (p == INVALID_ADDRESS) {
	    msg_err("tb: failed to allocate object\n");
	}
	vector_set(objs, i, p);
    } while (i--);

    /* and return */
    i = opp - 1;
    do {
	void * p = vector_get(objs, i);
	msg_debug("dealloc %p\n", p);
	deallocate(h, p, size);
    } while (i--);

    /* re-allocate a page's worth */
    i = opp - 1;
    do {
	void * p = allocate(h, size);
	if (p == INVALID_ADDRESS) {
	    msg_err("tb: failed to allocate object\n");
	}
	vector_set(objs, i, p);
    } while (i--);

    /* and one more to trigger a new page */
    void * p = allocate(h, size);

    h->destroy(h);
    return true;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    bytes pagesize = PAGESIZE;
    bytes mallocsize = pagesize * 1024; /* arbitrary */

    /* unix runtime doesn't set a pagesize, not sure if fragmentor
       will work without it...malloc heap ignores it */
    h->pagesize = mallocsize;

    /* make a parent heap for pages */
    heap pageheap = allocate_fragmentor(h, h, pagesize);

    if (!objcache_test(h, pageheap))
	return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
