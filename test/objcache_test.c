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

#ifdef OBJCACHE_DEBUG
#define msg_debug(fmt, ...) rprintf("%s debug: " fmt, __func__, \
				    ##__VA_ARGS__);
#else
#define msg_debug(fmt, ...)
#endif

boolean objcache_validate(heap h);

static inline boolean validate(heap h)
{
    if (!objcache_validate(h)) {
	msg_err("objcache_validate failed\n");
	return false;
    }

    return true;
}

static boolean alloc_vec(heap h, int n, int s, vector v)
{
    int i = n - 1;
    do {
	if (!validate(h))
	    return false;

	void * p = allocate(h, s);
	if (p == INVALID_ADDRESS) {
	    msg_err("tb: failed to allocate object\n");
	    return false;
	}
	
	vector_set(v, i, p);
    } while (i--);

    return true;
}

static boolean dealloc_vec(heap h, int n, int s, vector v)
{
    int i = n - 1;
    do {
	if (!validate(h))
	    return false;
	
	void * p = vector_get(v, i);
	deallocate(h, p, s);
    } while (i--);

    return true;
}
    
#define FOOTER_SIZE 24
boolean objcache_test(heap meta, heap parent, int objsize, int n_objs)
{
    /* just a cursory test */
    int opp = (PAGESIZE - FOOTER_SIZE) / objsize;
    int i;
    heap h = allocate_objcache(meta, parent, objsize);
    vector objs = allocate_vector(meta, n_objs);

    msg_debug("objs %p, heap %p\n", objs, h);
    
    if (h == INVALID_ADDRESS) {
	msg_err("tb: failed to allocate objcache heap\n");
	/* XXX free vector */
	return false;
    }

    /* allocate a page's worth */
    if (!alloc_vec(h, opp, objsize, objs))
	return false;

    /* and return (cache) them */
    if (!dealloc_vec(h, opp, objsize, objs))
	return false;
    
    /* re-allocate a page's worth + 1 to trigger parent allocation */
    if (!alloc_vec(h, opp + 1, objsize, objs))
	return false;
    
    /* and return them */
    if (!dealloc_vec(h, opp + 1, objsize, objs))
	return false;
    
    h->destroy(h);
    return true;
}

/* corny way to fake page alignment */
typedef struct malign {
    struct heap h;
    heap parent;
    u64 alignment;
} *malign;

u64 malign_alloc(heap h, bytes size)
{
    malign m = (malign)h;
    u64 len = pad(size, m->h.pagesize) + m->alignment - 1;
    u64 a = allocate_u64(m->parent, len);
    a += m->alignment - 1;
    return a - (a % m->alignment);
}

heap allocate_malign(heap meta, heap parent, bytes size, bytes alignment)
{
    malign m = allocate(meta, sizeof(struct malign));

    m->parent = parent;
    m->alignment = alignment;
    m->h.alloc = malign_alloc;
    m->h.dealloc = leak;
    m->h.pagesize = size;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    bytes pagesize = PAGESIZE;
    bytes mallocsize = pagesize * 1024; /* arbitrary */

    /* make a parent heap for pages */
    heap m = allocate_malign(h, h, mallocsize, pagesize);
    heap pageheap = allocate_fragmentor(h, m, pagesize);

    /* XXX test a range of sizes */
    if (!objcache_test(h, pageheap, 32, 1024))
	exit(EXIT_FAILURE);

    msg_debug("test passed\n");
    
    exit(EXIT_SUCCESS);
}
