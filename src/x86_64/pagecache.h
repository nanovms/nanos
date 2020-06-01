/* cache index to volume index, in bytes */
typedef closure_type(block_mapper, u64, u64);

typedef struct pagelist {
    struct list l;
    u64 pages;
} *pagelist;

typedef struct pagecache {
    u64 total_pages;
    u64 length;                 /* hard limit */
    int page_order;
    int block_order;
    heap h;
    heap backed;

    /* pages_lock covers traversal, insertions and removals
       should be some kind of rw lock */
    struct spinlock pages_lock;
    struct rbtree pages;

    /* state_lock covers list access, page state changes and
       alterations to page completion vecs */
    struct spinlock state_lock;
    struct pagelist free;      /* see state descriptions */
    struct pagelist new;
    struct pagelist active;
    struct pagelist writing;
    struct pagelist dirty;     /* phase 2 */

    /* fs callbacks */
    block_mapper mapper;

    /* block device interface */
    block_io block_read;
    block_io block_write;

    /* interface exposed to fs */
    sg_block_io sg_read;
    block_io write;
    block_sync sync;

    /* not under lock */
    queue completion_vecs;
    thunk service_completions;
    boolean service_enqueued;
} *pagecache;

typedef struct pagecache_node {
    pagecache pc;
    struct list l;              /* cache-wide node list */
    struct spinlock pages_lock;
    rbtree pages;
} *pagecache_node;

#define PAGECACHE_PAGESTATE_SHIFT   61

#define PAGECACHE_PAGESTATE_FREE    0 /* unused, yet may remain in search tree and retain usage stats */
#define PAGECACHE_PAGESTATE_EVICTED 1 /* evicted, awaiting release by user (not on list) */
#define PAGECACHE_PAGESTATE_ALLOC   2 /* allocated, request not issued (not on list) */
#define PAGECACHE_PAGESTATE_READING 3 /* block reads issued (not on list) */
#define PAGECACHE_PAGESTATE_NEW     4 /* newly-loaded and full page writes - can be reclaimed */
#define PAGECACHE_PAGESTATE_ACTIVE  5 /* cache hit for page */
#define PAGECACHE_PAGESTATE_DIRTY   6 /* page not synced */
#define PAGECACHE_PAGESTATE_WRITING 7 /* block writes in progress; back to tail of new on completion */

/* presently assuming pages are contiguous on storage
   TODO: - fix for block size > pagesize
         - reorg for single cacheline
         - move state to kvirt low order bits?
*/

typedef struct pagecache_page {
    struct rbnode node;         /* 3 */
    struct refcount refcount;   /* 2 */
    u64 offset;                 /* node offset in pages */
    void *kvirt;
    u64 state_phys;             /* state and physical page number */
    /* end of first cacheline */

    struct list l;
    u64 backing;                /* backing offset in blocks */
    merge write_merge;          /* completion merge for pending block writes */
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

static inline block_sync pagecache_syncer(pagecache pc)
{
    return pc->sync;
}

u64 pagecache_drain(pagecache pc, u64 drain_bytes);

pagecache allocate_pagecache(heap general, heap backed,
                             u64 length, u64 pagesize, u64 block_size,
                             block_mapper mapper, block_io read, block_io write);
