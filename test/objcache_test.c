#include <unix_process_runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

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
    for (int i=0; i < n; i++) {
	if (!validate(h))
	    return false;

	void * p = allocate(h, s);
	if (p == INVALID_ADDRESS) {
	    msg_err("tb: failed to allocate object\n");
	    return false;
	}
	
	vector_set(v, i, p);
    }

    return true;
}

static boolean dealloc_vec(heap h, int s, vector v)
{
    void * p;
    
    vector_foreach(v, p) {
	if (!p)
	    continue;
	
	if (!validate(h))
	    return false;
	
	deallocate(h, p, s);
    }

    return true;
}
    
#define FOOTER_SIZE 24
boolean objcache_test(heap meta, heap parent, int objsize)
{
    /* just a cursory test */
    int opp = (PAGESIZE - FOOTER_SIZE) / objsize;
    int i;
    heap h = allocate_objcache(meta, parent, objsize);
    vector objs = allocate_vector(meta, opp);

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
    if (!dealloc_vec(h, objsize, objs))
	return false;
    
    /* re-allocate a page's worth + 1 to trigger parent allocation */
    if (!alloc_vec(h, opp + 1, objsize, objs))
	return false;
    
    /* and return them */
    if (!dealloc_vec(h, objsize, objs))
	return false;
    
    h->destroy(h);
    return true;
}

u64 mmapheap_alloc(heap h, bytes size)
{
    void * rv = mmap(0, pad(size, h->pagesize), PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rv == MAP_FAILED) {
	msg_err("mmap() failed: errno %d (%s)\n", errno, strerror(errno));
	return INVALID_PHYSICAL;
    } else {
	return u64_from_pointer(rv);
    }
}

heap allocate_mmapheap(heap meta, bytes size, bytes alignment)
{
    heap h = allocate(meta, sizeof(struct heap));
    
    h->alloc = mmapheap_alloc;
    h->dealloc = leak;
    h->pagesize = size;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    bytes pagesize = PAGESIZE;
    bytes mmapsize = pagesize * 1024; /* arbitrary */

    /* make a parent heap for pages */
    heap m = allocate_mmapheap(h, mmapsize, pagesize);
    heap pageheap = allocate_fragmentor(h, m, pagesize);

    /* XXX test a range of sizes */
    if (!objcache_test(h, pageheap, 32))
	exit(EXIT_FAILURE);

    msg_debug("test passed\n");
    
    exit(EXIT_SUCCESS);
}
