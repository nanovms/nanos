/* want to support:

   1) scatter gather request with the consumer owning/providing the
      sg_vec but producer owning the frags/pages

      - use of refcount to manage access to frags

   ... but what if the requester passed an sg handler?
      + release could be per request, not per page
        - still is per page internally within pagecache
          + but producer may take more optimal steps
            1. e.g. allocate larger orders to backed heap and use ranges internally
      + consumer can use refcount as well when sharing 

      - the consumer supplying the sg list allows for an operation
        that spans extents and pages neatly synthesizes into one
        result list

   Another way to look at it: the scatter gather operation is a
   transaction that is divided into smaller transactions - each with
   two phases: request and completion. To begin, a transaction
   activation record is allocated along with an identifier. The front
   side (consumer) makes a request using a pointer to the record
   (sg_vec). The request handler takes a reference to the sg_vec 


*/

typedef struct sg_buf {
    void *buf;                  /* beginning of fragment */
    u32 length;                 /* [buf, buf + length) */
    u32 misc;                   /* padding, could be used as offset/index */
    refcount refcount;          /* reference held for source (e.g. page) */
} *sg_buf;

/* represents a scatter-gather transaction - global kernel object */
typedef struct sg_list {
    buffer b;                   /* buffer (array) of sg_bufs */
    word count;                 /* total bytes accumulated */
    struct list l;              /* for free list */
} *sg_list;

typedef closure_type(sg_block_io, void, sg_list, range, status_handler);

static inline sg_buf sg_list_tail_add(sg_list sg, word length)
{
    buffer_extend(sg->b, sizeof(struct sg_buf));
    void *sgf = buffer_ref(sg->b, buffer_length(sg->b));
    buffer_produce(sg->b, sizeof(struct sg_buf));
    fetch_and_add(&sg->count, length);
    return sgf;
}

/* Once an sg_buf is removed from the list, it must be later released
   with sg_buf_release. Unremoved items from the list can be released
   at once with sg_list_finish. */

static inline sg_buf sg_list_head_remove(sg_list sg)
{
    if (buffer_length(sg->b) < sizeof(struct sg_buf))
        return INVALID_ADDRESS;
    sg_buf sgf = (sg_buf)buffer_ref(sg->b, 0);
    fetch_and_add(&sg->count, -sgf->length);
    buffer_consume(sg->b, sizeof(struct sg_buf));
    return sgf;
}

static inline void sg_buf_release(sg_buf sgf)
{
    refcount_release(sgf->refcount);
}

static inline void sg_list_release(sg_list sg)
{
    sg_buf sgb;
    while ((sgb = sg_list_head_remove(sg)) != INVALID_ADDRESS) {
        sg_buf_release(sgb);
    }
}

sg_list allocate_sg_list(void);
void deallocate_sg_list(sg_list sgo);
void init_sg(heap h);
u64 sg_copy_to_buf_and_release(void *dest, sg_list src, u64 limit);
sg_block_io sg_wrapped_block_reader(block_io bio, int block_order, heap backed);
