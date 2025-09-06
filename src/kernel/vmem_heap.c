#include <kernel.h>

typedef struct vmem_heap {
    struct heap h;
    heap physical;
    heap virtual;
} *vmem_heap;

static void vmem_dealloc(heap h, u64 a, bytes len)
{
    bytes pagesize = h->pagesize;
    len = pad(len, pagesize);
    for (u64 v = a; v < a + len; v += pagesize) {
        unmap(v, pagesize);
    }
    vmem_heap vmh = (vmem_heap)h;
    deallocate(vmh->virtual, a, len);
}

static u64 vmem_alloc(heap h, bytes len)
{
    vmem_heap vmh = (vmem_heap)h;
    bytes pagesize = h->pagesize;
    len = pad(len, pagesize);
    u64 v = allocate_u64(vmh->virtual, len);
    if (v != INVALID_PHYSICAL) {
        heap physical = vmh->physical;
        pageflags flags = pageflags_writable(pageflags_memory());
        u64 virt_offset = 0;
        do {
            u64 phys_len = len - virt_offset;
            u64 p;
            while (true) {
                p = allocate_u64(physical, phys_len);
                if ((p != INVALID_PHYSICAL) || (phys_len == pagesize))
                    break;
                phys_len = pad(phys_len >> 1, pagesize);
            }
            if (p != INVALID_PHYSICAL) {
                map(v + virt_offset, p, phys_len, flags);
                virt_offset += phys_len;
            } else if (phys_len == pagesize) {
                break;
            }
        } while (virt_offset < len);
        if (virt_offset < len) {    /* physical memory allocation failed */
            vmem_dealloc(h, v, virt_offset);
            v = INVALID_PHYSICAL;
        }
    }
    return v;
}

heap create_vmem_heap(void)
{
    kernel_heaps kh = get_kernel_heaps();
    vmem_heap vmh = allocate(kh->locked, sizeof(*vmh));
    if (vmh != INVALID_ADDRESS) {
        vmh->h.alloc = vmem_alloc;
        vmh->h.dealloc = vmem_dealloc;
        vmh->h.allocated = 0;
        vmh->h.total = 0;
        vmh->h.management = 0;
        vmh->physical = heap_physical(kh);
        vmh->virtual = &heap_virtual_page(kh)->h;
        vmh->h.pagesize = vmh->physical->pagesize;
    }
    return &vmh->h;
}
