/* cache index to volume index, in bytes */
typedef closure_type(block_mapper, u64, u64);

struct pagelist {
    struct list l;
    u64 pages;
};

typedef struct pagecache {
    int page_order;
    int block_order;
    struct spinlock lock;
    rangemap pages;
    struct pagelist free;      /* see state descriptions */
    struct pagelist new;
    struct pagelist active;
    struct pagelist dirty;     /* phase 2 */
    u64 total_pages;
    u64 length;                 /* hard limit */
    heap h;
    heap backed;
    block_mapper mapper;
    block_io block_read;
    block_io block_write;
    sg_block_io sg_read;
    block_io write;
} *pagecache;

#define PAGECACHE_PAGESTATE_SHIFT   61

#define PAGECACHE_PAGESTATE_FREE    0 /* unused, yet may remain in search tree and retain usage stats */
#define PAGECACHE_PAGESTATE_EVICTED 1 /* evicted, awaiting release by user (not on list) */
#define PAGECACHE_PAGESTATE_ALLOC   2 /* allocated, request not issued (not on list) */
#define PAGECACHE_PAGESTATE_READING 3 /* block reads issued (not on list) */
#define PAGECACHE_PAGESTATE_NEW     4 /* newly-loaded and full page writes - can be reclaimed */
#define PAGECACHE_PAGESTATE_ACTIVE  5 /* cache hit for page */
#define PAGECACHE_PAGESTATE_DIRTY   6 /* page not synced */
#define PAGECACHE_PAGESTATE_WRITING 7 /* block writes in progress; back to tail of new on completion */

/* TODO fix for block size > pagesize */
typedef struct pagecache_page {
    struct rmnode node;
    struct refcount refcount;
    struct list l;
    struct spinlock lock;       /* cover changes to state / completions */
    void *kvirt;
    u64 state_phys;             /* state and physical page number */
    vector completions;         /* status_handlers */
} *pagecache_page;

static inline void pagecache_release_page(pagecache_page pp)
{
    refcount_release(&pp->refcount);
}

static inline sg_block_io pagecache_reader_sg(pagecache pc)
{
    return pc->sg_read;
}

static inline block_io pagecache_writer(pagecache pc)
{
    return pc->write;
}

u64 pagecache_drain(pagecache pc, u64 drain_bytes);
pagecache allocate_pagecache(heap general, heap backed,
                             u64 length, u64 pagesize, u64 block_size,
                             block_mapper mapper, block_io read, block_io write);
