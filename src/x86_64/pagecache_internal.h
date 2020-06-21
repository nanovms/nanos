typedef struct pagelist {
    struct list l;
    u64 pages;
} *pagelist;

typedef struct pagecache {
    word total_pages;
    int page_order;
    heap h;
    heap contiguous;

    /* state_lock covers list access, page state changes and
       alterations to page completion vecs */
    struct spinlock state_lock;
    struct pagelist free;      /* see state descriptions */
    struct pagelist new;
    struct pagelist active;
    struct pagelist writing;
    struct pagelist dirty;     /* phase 2 */
    struct list volumes;

    /* not under lock */
    queue completion_vecs;
    thunk service_completions;
    boolean service_enqueued;
} *pagecache;

/* we could make a universal interface type to storage rather than
   initialize with a handful of callbacks...does it matter? */

/* enumerate calls:

   fs -> pc
   - allocate (open) node
     - pass:
       - page_fill and page_sync
         - these may be used by a pagecache stub, so keep them dumb
       - initial node length
   - node extend or truncate
   - node read of arbitrary byte range
   - node write of arbitrary byte range
   - flush dirty buffers for file
   - invalidate
   - deallocate (close) node
   - node removed: close/destroy

   pc -> fs
   - page_fill
   - page_write

   walk through unaligned write from syscall

   - fs can simply pass write request as-is to pagecache, which will then:
     - determine the page(s) of the start and end of the request

       - if one of these is not in the cache and the write request
         doesn't entirely cover it, first request it

         - pretty sure we already do this? but if not, steal from tfs

       - post write as usual, but now we call back into the fs instead
         of to the block device

         - it seems page reads need to be entire ... but not writes? 


   cluster page, maybe split out as a rider PR or at least separate
   commit in merge, for non-zero risk:

   - allocate a special page which actually contains an array of
     smaller 4k pages

     - yet it is all physically contiguous

     - stipulation is that, aside from I/O, 4k chunks are treated as
       normal pages

     - problem: 4k pages winding up on different page lists

       - but we can still treat them independently, and 4k pages can
         be purged - after all they are picked up by the refcount
         completion, which in turn is a refcount for the superpage

         - a page refcount completion would clear an associated bit in
           a bitmap tracking the presence of a page in the cluster

           - for a really simplistic implementation, just revert to 4k
             writes if any of the pages have been evicted

             - much of the time we won't be dealing with eviction
               anyway unless configuration is really tight and we hit
               the reclaim threshold

         - another reason why I think the final refcount completion -
           whether cluster or small page - might be an ideal entry
           point back into the tlb shootdown / free page list
           mechanism - we won't have to worry about physical 4k
           portions being recycled while others are in use

     - refcount of refcounts!

   - cut down frequency of per-page allocations by factor of 512

   - sort of gives a poor-man's readahead

   - one downside is that each 4k page needs an entry in the rbtree
     (however not every one needs to be looked up - so maybe not critical?)
     - switching back to rangemap would take care of it

       - even though I just removed it, I'm kind of leaning towards
         this - very flexible apporach to support arbitrary lengths
         ... perhaps even fs extents can just be imported and
         pre-allocated in cache

     - good chance it doesn't matter at all, especially as there are
       no additional allocations to do so - just more tree entries
       so slower lookup
       - by what factor?


   - takes advantage of 2M pages on intel, but generally useful even
     for small page sizes

   - optional, single 4k page allocations are fine too - this just
     amortizes latency of allocation, mapping, etc. over more data at
     a time

   - allows longer contiguous I/O requests
 */

typedef struct pagecache_volume {
    struct list l;              /* volumes list */
    pagecache pc;
    struct list nodes;          /* head of pagecache_nodes */
    u64 length;                 /* end of volume */
    int block_order;
} *pagecache_volume;

typedef struct pagecache_node {
    struct list l;              /* volume-wide node list */
    pagecache_volume pv;

    /* pages_lock covers traversal, insertions and removals - consider
       changing to a rw lock or semaphore */
    struct spinlock pages_lock;
    struct rbtree pages;
    u64 length;

    sg_io cache_read;
    sg_io cache_write;
    sg_io fs_read;
    sg_io fs_write;
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
    struct rbnode rbnode;       /* 3 */
    struct refcount refcount;   /* 2 */
    u64 offset;                 /* node offset in pages */
    void *kvirt;
    u64 state_phys;             /* state and physical page number */
    /* end of first cacheline */

    pagecache_node node;
    struct list l;
    merge write_merge;          /* completion merge for pending block writes */
    vector completions;         /* status_handlers */
} *pagecache_page;

static inline void pagecache_release_page(pagecache_page pp)
{
    refcount_release(&pp->refcount);
}
