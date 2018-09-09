#include <runtime.h>
#include <sys/mman.h>
#include <errno.h>

void mmapheap_dealloc(heap h, u64 x, bytes size)
{
    if (munmap((void *)x, size))
        halt("munmap failed %E\n", errno);
}

u64 mmapheap_alloc(heap h, bytes size)
{
    void * rv = mmap(0, pad(size, h->pagesize), PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rv == MAP_FAILED) {
	msg_err("mmap() failed: errno %E", errno);
	return INVALID_PHYSICAL;
    } else {
	return u64_from_pointer(rv);
    }
}

heap allocate_mmapheap(heap meta, bytes size)
{
    heap h = allocate(meta, sizeof(struct heap));
    h->alloc = mmapheap_alloc;
    h->dealloc = mmapheap_dealloc;
    h->pagesize = pad(size, 4096);
    return h;
}
