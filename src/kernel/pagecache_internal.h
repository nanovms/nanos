typedef struct pagelist {
    struct list l;
    u64 pages;
} *pagelist;

typedef struct page_completion {
    struct list l;
    union {
        status_handler sh;
        status s;               /* queued list head has status to apply */
    };
} *page_completion;

typedef struct pagecache {
    word total_pages;
    int page_order;
    heap h;
    heap contiguous;
    heap completions;
    heap pp_heap;

    void *zero_page;            /* for zero-fill dma */

    /* state_lock covers list access, page state changes and
       alterations to page completion vecs */
#ifdef KERNEL
    struct spinlock state_lock;
    struct spinlock global_lock;
#endif
    struct pagelist free;      /* see state descriptions */
    struct pagelist new;
    struct pagelist active;
    struct pagelist writing;
    struct list volumes;
    struct list shared_maps;
    struct list private_maps;
    timestamp map_purge;

    boolean writeback_in_progress;
    struct timer scan_timer;
    closure_struct(timer_handler, do_scan_timer);
    closure_struct(status_handler, writeback_complete);
    closure_struct(rb_key_compare, page_compare);
    closure_struct(rbnode_handler, page_print_key);
} *pagecache;

typedef struct pagecache_volume {
    struct list l;              /* volumes list */
    pagecache pc;
    struct spinlock lock;
    struct list dirty_nodes;    /* head of pagecache_nodes */
    u64 length;                 /* end of volume */
    int block_order;
} *pagecache_volume;

typedef struct pagecache_node {
    struct list l;              /* volume-wide node list */
    pagecache_volume pv;

    /* pages_lock covers traversal, insertions and removals - consider
       changing to a rw lock or semaphore */
#ifdef KERNEL
    struct spinlock pages_lock;
#endif
    struct rbtree pages;
    struct rangemap dirty;
    struct list ops;
    u64 length;

    /* shared and private mappings associated with this node; protected by pagecache global lock */
    struct rangemap mappings;

    sg_io cache_read;
    sg_io cache_write;
    sg_io fs_read;
    sg_io fs_write;
    pagecache_node_reserve fs_reserve;
    closure_struct(thunk, free);
    closure_struct(thunk, queue_free);
    struct refcount refcount;   /* count dirty pages before freeing node */
} *pagecache_node;

struct pagecache_node_op_common {
    struct list l;
    enum {
        PAGECACHE_NODE_OP_COMMIT,
        PAGECACHE_NODE_OP_COMPLETE,
    } type;
};

declare_closure_struct(3, 1, void, pagecache_commit_dirty_ranges,
                       pagecache_node, pn, buffer, dirty, status_handler, complete,
                       status s);
struct pagecache_node_op_commit {
    struct pagecache_node_op_common common;
    closure_struct(pagecache_commit_dirty_ranges, commit);
};

struct pagecache_node_op_complete {
    struct pagecache_node_op_common common;
    status_handler sh;
};

typedef struct pagecache_map {
    struct rmnode n;            /* pn->mappings */
    struct list l;              /* pc->shared_maps or pc->private_maps */
    pagecache_node pn;
    u64 node_offset;            /* file offset of va.start */
    boolean shared;
} *pagecache_map;

#define PAGECACHE_PAGESTATE_SHIFT   61

#define PAGECACHE_PAGESTATE_FREE    0 /* evicted, yet remains in search tree and retains refault data */
#define PAGECACHE_PAGESTATE_EVICTED 1 /* evicted, awaiting release by user (not on list) */
#define PAGECACHE_PAGESTATE_ALLOC   2 /* allocated, request not issued (not on list) */
#define PAGECACHE_PAGESTATE_READING 3 /* block reads issued (not on list) */
#define PAGECACHE_PAGESTATE_NEW     4 /* newly-loaded and full page writes - can be reclaimed */
#define PAGECACHE_PAGESTATE_ACTIVE  5 /* cache hit for page */
#define PAGECACHE_PAGESTATE_DIRTY   6 /* page not synced */
#define PAGECACHE_PAGESTATE_WRITING 7 /* block writes in progress; back to tail of new on completion */

typedef struct pagecache_page *pagecache_page;

struct pagecache_page {
    struct rbnode rbnode;
    struct refcount read_refcount;  /* 24 */
    u64 state_offset;           /* 40 - state and offset in pages */
    void *kvirt;                /* 48 */
    int write_count;            /* 56 */
    int refcount;               /* 60 */
    /* end of first cacheline */

    pagecache_node node;
    struct list l;
    u64 phys;                   /* physical address */
    struct list bh_completions; /* default for non-kernel use */

    closure_struct(thunk, read_release);
    boolean evicted;
};
