#include <runtime.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

void mmapheap_dealloc(heap h, u64 x, bytes size)
{
    if (munmap((void *)x, size))
        halt("munmap failed %s\n", errno_sstring());
}

u64 mmapheap_alloc(heap h, bytes size)
{
    void * rv = mmap(0, size + h->pagesize, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rv == MAP_FAILED) {
	msg_err("mmap() failed: errno %s", errno_sstring());
	return INVALID_PHYSICAL;
    } else {
        return (u64_from_pointer(rv) + h->pagesize - 1) & ~(h->pagesize - 1);
    }
}

heap allocate_mmapheap(heap meta, bytes size)
{
    heap h = mem_alloc(meta, sizeof(struct heap), MEM_ZERO | MEM_NOFAIL);
    h->alloc = mmapheap_alloc;
    h->dealloc = mmapheap_dealloc;
    h->pagesize = pad(size, 4096);
    return h;
}
