#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define TEST_PAGESIZE  (1 << 21)

static inline boolean validate(heap h)
{
    if (!objcache_validate(h)) {
	msg_err("objcache_validate failed\n");
	return false;
    }

    return true;
}

static inline boolean validate_obj(heap h, void * obj)
{
    heap o = objcache_from_object(u64_from_pointer(obj), TEST_PAGESIZE);
    if (o != h) {
	msg_err("objcache_from_object returned %p, doesn't match heap %p\n", o, h);
	return false;
    }
    return true;
}

static boolean alloc_vec(heap h, int n, int s, vector v)
{
    if (!validate(h))
	return false;
    for (int i=0; i < n; i++) {
	void * p = allocate(h, s);
	if (p == INVALID_ADDRESS) {
	    msg_err("tb: failed to allocate object\n");
	    return false;
	}
	if (!validate_obj(h, p))
	    return false;
	
	vector_set(v, i, p);
    }
    if (!validate(h))
	return false;

    return true;
}

static boolean dealloc_vec(heap h, int s, vector v)
{
    void * p;
    if (!validate(h))
	return false;
    vector_foreach(v, p) {
	if (!p)
	    continue;

	if (!validate_obj(h, p))
	    return false;

	deallocate(h, p, s);
    }
    if (!validate(h))
	return false;
    return true;
}
    
#define FOOTER_SIZE 24
boolean objcache_test(heap meta, heap parent, int objsize)
{
    /* just a cursory test */
    int opp = (TEST_PAGESIZE - FOOTER_SIZE) / objsize;
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

    if (h->allocated > 0) {
	msg_err("allocated (%d) should be 0; fail\n", h->allocated);
	return false;
    }
    h->destroy(h);
    return true;
}

u64 mmapheap_alloc(heap h, bytes size)
{
    void * rv = mmap(0, size + TEST_PAGESIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rv == MAP_FAILED) {
	msg_err("mmap() failed: errno %d (%s)\n", errno, strerror(errno));
	return INVALID_PHYSICAL;
    } else {
	return (u64_from_pointer(rv) + TEST_PAGESIZE - 1) & ~(TEST_PAGESIZE - 1);
    }
}

heap allocate_mmapheap(heap meta, bytes size)
{
    heap h = allocate(meta, sizeof(struct heap));
    h->alloc = mmapheap_alloc;
    h->dealloc = leak;
    h->pagesize = size;
    return h;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    bytes mmapsize = TEST_PAGESIZE * 4; /* arbitrary */

    /* make a parent heap for pages */
    heap m = allocate_mmapheap(h, mmapsize);
    heap pageheap = create_id_heap_backed(h, m, TEST_PAGESIZE);

    /* XXX test a range of sizes */
    if (!objcache_test(h, pageheap, 32))
	exit(EXIT_FAILURE);

    msg_debug("test passed\n");
    
    exit(EXIT_SUCCESS);
}
