/* Heap that implements a buddy memory allocator. */

#include <runtime.h>

#define PAGEHEAP_MAX_ORDER  9

#define PAGEHEAP_AREA_MAX_PAGES U64_FROM_BIT(16)

#define PAGE_INDEX_INVALID  0xffff

//#define PAGEHEAP_DEBUG
#if defined(PAGEHEAP_DEBUG)
#define pageheap_debug(x, ...)  rprintf("pageheap: " x "\n", ##__VA_ARGS__)
#else
#define pageheap_debug(x, ...)
#endif

typedef struct pageheap_range {
    struct rmnode n;
    u64 inited;
} *pageheap_range;
build_assert(offsetof(pageheap_range, n) == 0);

typedef struct page_list_elem {
    u16 prev, next;
} *page_list_elem;

typedef struct pageheap_area {
    struct list l;
    u64 buddies[PAGEHEAP_AREA_MAX_PAGES / 64];  /* 1 bit per pair of buddies per page order */
    u32 page_count;
    u16 first[PAGEHEAP_MAX_ORDER + 1];  /* first elements in free page lists */
    struct page_list_elem free_pages[0];
} *pageheap_area;

static struct page_heap {
    struct heap h;
    heap meta;
    struct rangemap ranges;
    u64 total;
    u64 allocated;
    void *virt_base;
    int max_order;
    /* A page area is inserted in the list corresponding to the order of the largest free page
     * present in the area. */
    struct list areas[PAGEHEAP_MAX_ORDER + 1];
    struct spinlock lock;
} page_heap;
build_assert(offsetof(struct page_heap *, h) == 0);

#define pageheap_header_size(page_count) \
    pad(sizeof(struct pageheap_area) + sizeof(struct page_list_elem) * (page_count), PAGESIZE)
#define pageheap_area_base(area)    \
    (u64_from_pointer((void *)area + pageheap_header_size((area)->page_count) -    \
                      page_heap.virt_base) &    \
     ~MASK(PAGELOG + page_heap.max_order))
#define PAGEHEAP_AREA_MIN_SIZE  (pageheap_header_size(1) + PAGESIZE)

#define pageheap_index(area, p) (((p) - pageheap_area_base(area)) / PAGESIZE)

#define page_buddy_index(i, order)  ((i) ^ U32_FROM_BIT(order))
#define page_buddy_first(i, order)  ((i) & ~U32_FROM_BIT(order))

static int page_buddy_bit(u16 index, int order)
{
    int base = 0;
    for (int o = 0; o < order; o++)
        base += PAGEHEAP_AREA_MAX_PAGES >> (o + 1);
    return base + (index >> (order + 1));
}

static void page_buddy_set(u64 *buddies, u16 index, int order)
{
    int bit = page_buddy_bit(index, order);
    u64 mask = 1ull << (bit & 63);
    u64 *p = buddies + bit / 64;
    pageheap_debug("setting buddy 0x%x, order %d", index, order);
    *p |= mask;
}

static void page_buddy_clear(u64 *buddies, u16 index, int order)
{
    int bit = page_buddy_bit(index, order);
    u64 mask = 1ull << (bit & 63);
    u64 *p = buddies + bit / 64;
    pageheap_debug("clearing buddy 0x%x, order %d", index, order);
    *p &= ~mask;
}

static boolean page_buddy_toggle(u64 *buddies, u16 index, int order)
{
    int bit = page_buddy_bit(index, order);
    u64 mask = 1ull << (bit & 63);
    u64 *p = buddies + bit / 64;
    boolean is_set = !!(*p & mask);
    pageheap_debug("toggling buddy 0x%x, order %d (was %d)", index, order, is_set);
    if (is_set)
        *p &= ~mask;
    else
        *p |= mask;
    return is_set;
}

static pageheap_area pageheap_area_new(void)
{
    u64 start, end;
    pageheap_range r = (pageheap_range)rangemap_first_node(&page_heap.ranges);
    while (r != INVALID_ADDRESS) {
        pageheap_debug("looking for new area in range %R (0x%lx)", r->n.r, r->inited);
        start = r->inited;
        end = r->n.r.end;
        u64 min_area_size = PAGEHEAP_AREA_MIN_SIZE / PAGESIZE;
        if (start + min_area_size <= end) {
            /* In order to be able to easily retrieve the page area associated to a page address
             * (needed in the deallocation function), an area must not cross a PAGE_AREA_MAX_PAGES
             * boundary. */
            u64 area_limit = pad(start + 1, PAGEHEAP_AREA_MAX_PAGES);
            if (start + min_area_size > area_limit) {
                start = r->inited = area_limit;
                area_limit += PAGEHEAP_AREA_MAX_PAGES;
            }
            if (start + min_area_size <= end) {
                if (end > area_limit)
                    end = area_limit;
                break;
            }
        }
        r = (pageheap_range)rangemap_next_node(&page_heap.ranges, &r->n);
    }
    if (r == INVALID_ADDRESS)
        return 0;
    u64 header_size;
    u16 page_align = MASK32(page_heap.max_order);
    u32 page_count = PAGEHEAP_AREA_MAX_PAGES;
  check_area_size:
    header_size = pageheap_header_size(page_count);
    u64 page_start = start + header_size / PAGESIZE;
    u16 page_offset = page_start & page_align;
    u64 area_end = page_start - page_offset + page_count;
    if (area_end > end) {
        u32 page_diff = area_end - end;
        if (page_diff >= page_count) {
            /* the usable page range must be small */
            page_count = page_align + header_size / PAGESIZE;
            goto check_area_size;
        }
        u64 header_diff = header_size - pageheap_header_size(page_count - page_diff);
        pageheap_debug("area overshoot 0x%x pages, header difference 0x%lx bytes",
                       page_diff, header_diff);
        if (header_diff) {
            /* Account for the pages saved by decreasing the header size; in addition, a change to
             * the header size can cause the end of the header to move across an alignment boundary
             * and change the maximum page count: thus, be conservative when decreasing the
             * candidate page_count, to ensure the entire usable page range is covered. */
            page_diff -= header_diff / PAGESIZE;
            if (page_diff > page_align)
                page_diff -= page_align;
            else
                page_diff = 1;
        }
        page_count -= page_diff;
        goto check_area_size;
    }
    pageheap_area area = page_heap.virt_base + start * PAGESIZE;
    pageheap_debug("new area at %p, pages [0x%x, 0x%x)", area, page_offset, page_count);
    area->page_count = page_count;
    zero(area->buddies, sizeof(area->buddies));
    for (int o = 0; o <= page_heap.max_order; o++)
        area->first[o] = PAGE_INDEX_INVALID;
    u16 last_index = PAGE_INDEX_INVALID;
    int order = 0;
    for (u32 index = page_offset; index < page_count; index += U32_FROM_BIT(order)) {
        while ((order < page_heap.max_order) && !(index & MASK32(order + 1))) {
            order++;
            last_index = PAGE_INDEX_INVALID;
        }
        while ((order > 0) && ((page_count - index) < U32_FROM_BIT(order))) {
            if ((order < page_heap.max_order) && (index != page_buddy_first(index, order)))
                /* the second buddy is past the end of the page range */
                page_buddy_set(area->buddies, index, order);
            order--;
            last_index = PAGE_INDEX_INVALID;
        }
        if (order < page_heap.max_order) {
            boolean first = (index == page_buddy_first(index, order));
            if ((last_index == PAGE_INDEX_INVALID) && !first)
                /* This is the first page of this order, and is the second buddy, which means the
                 * first buddy is before the start of the page range. */
                page_buddy_set(area->buddies, index, order);
        }

        /* Insert the page at the end of the free list. */
        if (last_index == PAGE_INDEX_INVALID) {
            u16 next = area->first[order];
            while (next != PAGE_INDEX_INVALID) {
                last_index = next;
                next = area->free_pages[last_index].next;
            }
        }
        page_list_elem e = &area->free_pages[index];
        e->prev = last_index;
        e->next = PAGE_INDEX_INVALID;
        if (last_index != PAGE_INDEX_INVALID)
            area->free_pages[last_index].next = index;
        else
            area->first[order] = index;
        last_index = index;
    }
    if ((order < page_heap.max_order) && (page_count != page_buddy_first(page_count, order)))
        /* the second buddy is past the end of the page range */
        page_buddy_set(area->buddies, page_count, order);
    for (order = page_heap.max_order; order >= 0; order--) {
        if (area->first[order] != PAGE_INDEX_INVALID) {
            list_push(&page_heap.areas[order], &area->l);
            break;
        }
    }
    r->inited += header_size / PAGESIZE + page_count - page_offset;
    return area;
}

static pageheap_area pageheap_area_from_page(u64 p)
{
    u64 base = p & ~(PAGEHEAP_AREA_MAX_PAGES * PAGESIZE - 1);
    rmnode n = rangemap_lookup(&page_heap.ranges, p >> PAGELOG);
    u64 range_start = n->r.start << PAGELOG;
    if (base < range_start)
        base = range_start;
    return base + page_heap.virt_base;
}

/* Inserts a page at the start of the free list, returns whether the list was empty. */
static boolean pageheap_add_free(pageheap_area area, u16 page_index, int order)
{
    pageheap_debug("adding free page at 0x%x, order %d", page_index, order);
    page_list_elem e = &area->free_pages[page_index];
    u16 next = area->first[order];
    e->prev = PAGE_INDEX_INVALID;
    e->next = next;
    area->first[order] = page_index;
    if (next != PAGE_INDEX_INVALID) {
        area->free_pages[next].prev = page_index;
        return false;
    }
    return true;
}

/* Removes a page from the free list, returns whether the list is empty. */
static boolean pageheap_remove_free(pageheap_area area, u16 page_index, int order)
{
    pageheap_debug("removing free page at 0x%x, order %d", page_index, order);
    page_list_elem e = &area->free_pages[page_index];
    u16 prev = e->prev;
    u16 next = e->next;
    if (next != PAGE_INDEX_INVALID)
        area->free_pages[next].prev = prev;
    if (prev != PAGE_INDEX_INVALID) {
        area->free_pages[prev].next = next;
        return false;
    } else {
        area->first[order] = next;
        return (next == PAGE_INDEX_INVALID);
    }
}

static int pageheap_dealloc_page(pageheap_area area, u16 index, int page_order)
{
    pageheap_debug("dealloc index 0x%x, order %d", index, page_order);
    int updated_order = -1;
    for (; page_order < page_heap.max_order; page_order++) {
        boolean buddy_is_free = page_buddy_toggle(area->buddies, index, page_order);
        if (buddy_is_free) {
            /* coalesce this page with its buddy */
            u16 buddy_index = page_buddy_index(index, page_order);
            if (pageheap_remove_free(area, buddy_index, page_order))
                updated_order = page_order;
            if (buddy_index < index)
                index = buddy_index;
        } else {
            if (pageheap_add_free(area, index, page_order))
                updated_order = page_order;
            break;
        }
    }
    if ((page_order == page_heap.max_order) && pageheap_add_free(area, index, page_order))
        updated_order = page_order;
    return updated_order;
}

static int pageheap_dealloc_locked(pageheap_area area, u32 index, u16 page_count)
{
    pageheap_debug("dealloc index 0x%x, count %d", index, page_count);
    u32 end_index = index + page_count;
    int updated_order = - 1;
    do {
        int index_order = lsb(index);
        int page_order = find_order(end_index - index);
        if ((index_order >= 0) && (index_order < page_order))
            page_order = index_order;
        if (index + U32_FROM_BIT(page_order) > end_index)
            page_order--;
        updated_order = MAX(updated_order, pageheap_dealloc_page(area, index, page_order));
        index += U32_FROM_BIT(page_order);
    } while (index < end_index);
    return updated_order;
}

static void pageheap_dealloc(heap h, u64 p, bytes size)
{
    pageheap_area area = pageheap_area_from_page(p);
    pageheap_debug("dealloc 0x%lx, size 0x%lx, area %p", p, size, area);
    spin_lock(&page_heap.lock);
    int updated_order = pageheap_dealloc_locked(area, pageheap_index(area, p), size / PAGESIZE);
    if (updated_order >= 0) {
        int max_free_order = 0;
        for (int page_order = page_heap.max_order; page_order >= updated_order; page_order--) {
            if (area->first[page_order] != PAGE_INDEX_INVALID) {
                max_free_order = page_order;
                break;
            }
        }
        pageheap_debug("dealloc: free order %d", max_free_order);
        if (max_free_order == updated_order) {
            pageheap_debug("dealloc: updating area list");
            list l = &area->l;
            if (list_inserted(l))
                list_delete(l);
            list_push(&page_heap.areas[max_free_order], l);
        }
    }
    page_heap.allocated -= size;
    spin_unlock(&page_heap.lock);
}

static u64 pageheap_alloc(heap h, bytes size)
{
    int page_order = find_order(size) - PAGELOG;
    pageheap_debug("alloc size 0x%lx, page order %d", size, page_order);
    if (page_order > page_heap.max_order)
        return INVALID_PHYSICAL;
    int list_order;
    list l;
    spin_lock(&page_heap.lock);
    for (list_order = page_order; list_order <= page_heap.max_order; list_order++) {
        l = list_get_next(page_heap.areas + list_order);
        if (l)
            break;
    }
    while (!l) {
        pageheap_area new_area = pageheap_area_new();
        if (!new_area)
            break;
        for (list_order = page_heap.max_order; list_order >= page_order; list_order--) {
            if (new_area->first[list_order] != PAGE_INDEX_INVALID) {
                l = &new_area->l;
                break;
            }
        }
    }
    u64 p;
    if (l) {
        pageheap_area area = struct_from_field(l, pageheap_area, l);
        boolean list_deleted = false;
        u16 page_index;
        int free_order;
        for (free_order = page_order; free_order <= page_heap.max_order; free_order++) {
            page_index = area->first[free_order];
            if (page_index != PAGE_INDEX_INVALID)
                break;
        }
        p = pageheap_area_base(area) + page_index * PAGESIZE;
        pageheap_debug("alloc: found free page in %p[0x%x], order %d: 0x%lx", area,
                       page_index, free_order, p);
        if (free_order < page_heap.max_order)
            page_buddy_clear(area->buddies, page_index, free_order);
        if (pageheap_remove_free(area, page_index, free_order) && (free_order == list_order)) {
            list_delete(l);
            list_deleted = true;
        }
        for (free_order--; free_order >= page_order; free_order--) {
            page_buddy_set(area->buddies, page_index, free_order);
            u16 buddy_index = page_buddy_index(page_index, free_order);
            pageheap_add_free(area, buddy_index, free_order);
        }
        u64 page_count = U64_FROM_BIT(page_order);
        u64 requested = size / PAGESIZE;
        if (page_count > requested)
            pageheap_dealloc_locked(area, page_index + requested, page_count - requested);
        if (list_deleted) {
            for (free_order = list_order - 1; free_order >= 0; free_order--) {
                if (area->first[free_order] != PAGE_INDEX_INVALID) {
                    list_push_back(&page_heap.areas[free_order], l);
                    break;
                }
            }
        }
        page_heap.allocated += size;
    } else {
        p = INVALID_PHYSICAL;
    }
    spin_unlock(&page_heap.lock);
    return p;
}

static bytes pageheap_allocated(heap h)
{
    return page_heap.allocated;
}

static bytes pageheap_total(heap h)
{
    return page_heap.total;
}

heap pageheap_init(heap meta)
{
    page_heap.h.alloc = pageheap_alloc;
    page_heap.h.dealloc = pageheap_dealloc;
    page_heap.h.allocated = pageheap_allocated;
    page_heap.h.total = pageheap_total;
    page_heap.h.pagesize = PAGESIZE;
    page_heap.meta = meta;
    init_rangemap(&page_heap.ranges, 0);
    return &page_heap.h;
}

boolean pageheap_add_range(u64 base, u64 length)
{
    u64 page_start = base >> PAGELOG;
    u64 pages = length >> PAGELOG;
    pageheap_range r = allocate(page_heap.meta, sizeof(*r));
    assert(r != INVALID_ADDRESS);
    rmnode_init(&r->n, irangel(page_start, pages));
    if (!rangemap_insert(&page_heap.ranges, &r->n)) {
        deallocate(page_heap.meta, r, sizeof(*r));
        return false;
    }
    r->inited = page_start;
    page_heap.total += length;
    return true;
}

void pageheap_init_done(void *virt_base, u64 max_page_size)
{
    page_heap.virt_base = virt_base;
    page_heap.max_order = find_order(max_page_size) - PAGELOG;
    for (int i = 0; i <= page_heap.max_order; i++)
        list_init(&page_heap.areas[i]);
    spin_lock_init(&page_heap.lock);
}

closure_function(1, 1, boolean, pageheap_rmnode_handler,
                 range_handler, rh,
                 rmnode n)
{
    apply(bound(rh), range_lshift(n->r, PAGELOG));
    return true;
}

void pageheap_range_foreach(range_handler rh)
{
    rangemap_range_lookup(&page_heap.ranges, irange(0, infinity),
                          stack_closure(pageheap_rmnode_handler, rh));
}

bytes pageheap_max_pagesize(void)
{
    return U64_FROM_BIT(page_heap.max_order + PAGELOG);
}
