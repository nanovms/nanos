#include <runtime.h>
#include <sys/mman.h>

#include "../test_utils.h"

#define PH_TEST_MAX_PAGESIZE    PAGESIZE_2M

static u64 ph_test_range(heap h, void *mem_base, range r, u64 max_page_size)
{
    heap ph = pageheap_init(h);
    u64 len = range_span(r);
    u64 addrs[4096];
    u64 last_allocated = 0, max_allocated = 0;
    boolean heap_filled = false;

    test_assert(pageheap_add_range(r.start, len));
    test_assert(!pageheap_add_range(r.start, PAGESIZE));    /* overlaps the already-added range */
    pageheap_init_done(mem_base, max_page_size);
    for (u64 alloc_size = PAGESIZE; alloc_size > 0; alloc_size <<= 1) {
        u64 align = MAX(alloc_size, max_page_size) / PAGESIZE - 1;
        int page_count;
        u64 allocated = 0;

        for (page_count = 0; page_count < _countof(addrs); page_count++) {
            u64 p = allocate_u64(ph, alloc_size);

            if (p != INVALID_PHYSICAL) {
                test_assert((p >= r.start) && (p + alloc_size <= r.end));
                test_assert(!(p & align));
                addrs[page_count] = p;
                allocated += alloc_size;
            } else {
                break;
            }
        }
        test_assert(heap_allocated(ph) == allocated);
        test_assert(allocated < len);   /* there is a non-null overhead in the heap */
        if (last_allocated != 0)
            test_assert(allocated <= last_allocated);   /* due to the larger alloc size */
        if (page_count < _countof(addrs)) {
            /* The last allocation request failed, i.e. all available pages of the current alloc
             * size have been allocated. */
            if (alloc_size == PAGESIZE)
                heap_filled = true;
            last_allocated = allocated;
        }
        if (allocated > max_allocated)
            max_allocated = allocated;

        for (int page = page_count - 1; page >= 0; page--)
            deallocate_u64(ph, addrs[page], alloc_size);
        test_assert(heap_allocated(ph) == 0);

        /* Re-do the same allocation requests as above, and verify that the same amount of memory
         * can be allocated (i.e. no memory has been leaked). */
        for (page_count = 0; page_count < _countof(addrs); page_count++) {
            u64 p = allocate_u64(ph, alloc_size);

            if (p != INVALID_PHYSICAL)
                addrs[page_count] = p;
            else
                break;
        }
        test_assert(page_count * alloc_size == allocated);

        for (int page = 0; page < page_count; page++)
            deallocate_u64(ph, addrs[page], alloc_size);
        test_assert(heap_allocated(ph) == 0);
    }

    if (heap_filled) {
        u64 sizes[_countof(addrs)];
        u64 p;
        int page_count = 0;

        /* Allocate all heap memory, starting with the largest alloc size and falling back to
         * smaller sizes on allocation failure. */
        last_allocated = 0;
        for (u64 alloc_size = max_page_size; alloc_size >= PAGESIZE; alloc_size >>= 1) {
            while ((p = allocate_u64(ph, alloc_size)) != INVALID_PHYSICAL) {
                addrs[page_count] = p;
                sizes[page_count] = alloc_size;
                page_count++;
                last_allocated += alloc_size;
            }
        }
        test_assert(last_allocated >= max_allocated);
        max_allocated = last_allocated;
        for (int page = 0; page < page_count; page++)
            deallocate_u64(ph, addrs[page], sizes[page]);
        test_assert(heap_allocated(ph) == 0);

        /* Allocate all heap memory using the smallest alloc size, and verify that the same amount
         * of memory as above can be allocated. */
        page_count = 0;
        last_allocated = 0;
        while ((p = allocate_u64(ph, PAGESIZE)) != INVALID_PHYSICAL) {
            addrs[page_count++] = p;
            last_allocated += PAGESIZE;
        }
        test_assert(last_allocated == max_allocated);
        for (int page = 0; page < page_count; page++)
            deallocate_u64(ph, addrs[page], PAGESIZE);
    }

    return max_allocated;
}

static void ph_test_basic(heap h, void *mem_base, u64 mem_size, u64 max_page_size)
{
    range r;

    for (r.start = 0; r.start <= max_page_size;) {
        u64 max_allocated[find_order(mem_size)];
        int range_len = 0;

        for (r.end = r.start + PAGESIZE; r.end <= mem_size; r.end *= 2) {
            max_allocated[range_len] = ph_test_range(h, mem_base, r, max_page_size);
            if (range_len > 0)
                test_assert(max_allocated[range_len] >= max_allocated[range_len - 1]);
            range_len++;
        }
        if (r.start == 0)
            r.start = PAGESIZE;
        else
            r.start *= 2;
    }
}

/* Test the most-recently-used allocation algorithm. */
static void ph_test_mru(heap h, void *mem_base, u64 mem_size)
{
    heap ph = pageheap_init(h);
    u64 addrs[2048];
    u64 p;
    u64 unaligned_base = 0, unaligned_len = 0;

    test_assert(pageheap_add_range(0, 3 * PH_TEST_MAX_PAGESIZE));
    pageheap_init_done(mem_base, PH_TEST_MAX_PAGESIZE);

    for (u64 alloc_size = PAGESIZE; alloc_size <= PH_TEST_MAX_PAGESIZE; alloc_size <<= 1) {
        int page_count;

        for (page_count = 0; page_count < _countof(addrs); page_count++) {
            p = allocate_u64(ph, alloc_size);

            if (p != INVALID_PHYSICAL)
                addrs[page_count] = p;
            else
                break;
        }
        test_assert(page_count >= 2);
        for (int page = page_count - 1; page >= 0; page--)
            deallocate_u64(ph, addrs[page], alloc_size);
        /* Verify that memory areas are allocated in reverse order compared to the oder of the last
         * deallocations. */
        for (page_count = 0; page_count < _countof(addrs); page_count++) {
            p = allocate_u64(ph, alloc_size);

            if (p != INVALID_PHYSICAL)
                test_assert(p == addrs[page_count]);
            else
                break;
        }
        for (int page = 0; page < page_count; page++)
            deallocate_u64(ph, addrs[page], alloc_size);
    }

    /* Verify that the same memory area is reused across different allocation sizes. */
    while (true) {
        /* To ensure the heap does not have free pages smaller than the maximum page size, allocate
         * small pages until an address aligned to the maximum page sizes is returned. */
        p = allocate_u64(ph, PAGESIZE);
        if (p & (PH_TEST_MAX_PAGESIZE - 1)) {
            if (unaligned_len == 0)
                unaligned_base = p;
            unaligned_len += PAGESIZE;
        } else {
            deallocate_u64(ph, p, PAGESIZE);
            break;
        }
    }
    for (u64 alloc_size = PH_TEST_MAX_PAGESIZE; alloc_size >= PAGESIZE; alloc_size >>= 1) {
        int alloc_count = PH_TEST_MAX_PAGESIZE / alloc_size;

        for (int i = 0; i < alloc_count; i++)
            test_assert(allocate_u64(ph, alloc_size) == p + i * alloc_size);
        for (int i = alloc_count - 1; i >= 0; i--)
            deallocate_u64(ph, p + i * alloc_size, alloc_size);
    }
    for (u64 alloc_size = PAGESIZE * 2; alloc_size <= PH_TEST_MAX_PAGESIZE; alloc_size <<= 1) {
        int alloc_count = PH_TEST_MAX_PAGESIZE / alloc_size;

        for (int i = 0; i < alloc_count; i++)
            test_assert(allocate_u64(ph, alloc_size) == p + i * alloc_size);
        for (int i = alloc_count - 1; i >= 0; i--)
            deallocate_u64(ph, p + i * alloc_size, alloc_size);
    }
    if (unaligned_len != 0)
        deallocate_u64(ph, unaligned_base, unaligned_len);
}

/* Test allocation and deallocation size values that are not power-of-2 (and thus are split into
 * multiple pages with different sizes). */
static void ph_test_multipage(heap h, void *mem_base, u64 mem_size)
{
    heap ph = pageheap_init(h);
    u64 base;

    test_assert(pageheap_add_range(0, 2 * PH_TEST_MAX_PAGESIZE));
    pageheap_init_done(mem_base, PH_TEST_MAX_PAGESIZE);

    /* Allocate a non-power-of-2 size and verify that the next memory area is still available for
     * subsequent allocations. */
    for (u64 alloc_size = 3 * PAGESIZE; alloc_size < PH_TEST_MAX_PAGESIZE; alloc_size += PAGESIZE) {
        u64 total_size = U64_FROM_BIT(find_order(alloc_size));
        u64 next_offset, next_size;

        if (alloc_size == total_size)
            continue;
        base = allocate_u64(ph, alloc_size);
        next_offset = alloc_size;
        do {
            next_size = 1 << lsb(next_offset);
            test_assert(allocate_u64(ph, next_size) == base + next_offset);
            next_offset += next_size;
        } while (next_offset < total_size);
        deallocate_u64(ph, base, total_size);
        test_assert(heap_allocated(ph) == 0);
    }

    /* Allocate a single large page and deallocate it in smaller chunks. */
    for (u64 boundary = PAGESIZE; boundary < PH_TEST_MAX_PAGESIZE; boundary += PAGESIZE) {
        base = allocate_u64(ph, PH_TEST_MAX_PAGESIZE);
        deallocate_u64(ph, base, boundary);
        test_assert(heap_allocated(ph) == PH_TEST_MAX_PAGESIZE - boundary);
        deallocate_u64(ph, base + boundary, PH_TEST_MAX_PAGESIZE - boundary);
        test_assert(heap_allocated(ph) == 0);
    }
    for (u64 offset = 0; offset < PH_TEST_MAX_PAGESIZE; offset += PAGESIZE) {
        test_assert(allocate_u64(ph, PH_TEST_MAX_PAGESIZE) == base);
        deallocate_u64(ph, base + offset, PAGESIZE);
        test_assert(heap_allocated(ph) == PH_TEST_MAX_PAGESIZE - PAGESIZE);
        if (offset > 0)
            deallocate_u64(ph, base, offset);
        if (offset + PAGESIZE < PH_TEST_MAX_PAGESIZE)
            deallocate_u64(ph, base + offset + PAGESIZE, PH_TEST_MAX_PAGESIZE - offset - PAGESIZE);
        test_assert(heap_allocated(ph) == 0);
    }
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    const u64 mem_size = 512 * MB;
    void *mem_base = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);

    test_assert(mem_base != MAP_FAILED);
    for (u64 max_page_size = PAGESIZE; max_page_size <= PH_TEST_MAX_PAGESIZE; max_page_size <<= 1)
        ph_test_basic(h, mem_base, mem_size, max_page_size);
    ph_test_mru(h, mem_base, mem_size);
    ph_test_multipage(h, mem_base, mem_size);
    munmap(mem_base, mem_size);
    return 0;
}
