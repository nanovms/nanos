/* cache index to volume index, in bytes */
typedef closure_type(block_mapper, u64, u64);

typedef struct pagecache {
    rangemap pages;
    struct spinlock lock;
    struct list free;           /* see state descriptions */
    struct list new;
    struct list active;
    struct list dirty;          /* phase 2 */
    int page_order;
    int block_order;            /* really only 9 or 12 at this point */
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

#define PAGECACHE_PAGESTATE_FREE    0 /* unused */
#define PAGECACHE_PAGESTATE_ALLOC   1 /* allocated, request not issued (not on list) */
#define PAGECACHE_PAGESTATE_READING 2 /* block reads issued (not on list) */
#define PAGECACHE_PAGESTATE_NEW     3 /* newly-loaded and full page writes - can be reclaimed */
#define PAGECACHE_PAGESTATE_ACTIVE  4 /* cache hit for page */
#define PAGECACHE_PAGESTATE_DIRTY   5 /* page not synced */
#define PAGECACHE_PAGESTATE_WRITING 6 /* block writes in progress; back to tail of new on completion */

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

pagecache allocate_pagecache(heap general, heap backed,
                             u64 length, u64 pagesize, u64 block_size,
                             block_mapper mapper, block_io read, block_io write);
