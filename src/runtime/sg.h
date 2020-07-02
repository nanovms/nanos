/* A scatter gather operation is a transaction that is divided into
   smaller transactions - each with two phases: request and
   completion. To begin, a transaction activation record and handle is
   allocated with allocate_sg_list. A consumer makes a request using
   the empty sg_list. On completion, the sg_list is filled with
   scatter-gather buffer data. As the consumer consumes buffers
   (sg_bufs), they are released with sg_buf_release - or the entire
   list and any unconsumed buffers are released at once with
   sg_list_release.

   A producing requester allocates the sg_list and populates it with
   scatter-gather buffer data before initiating a request. It must
   supply a refcount pointer for each buffer (which may all point to a
   single refcount for the request, essentially acting as a merge).
*/

typedef struct sg_buf {
    void *buf;                  /* beginning of fragment */
    u32 size;                   /* buffer size including offset portion */
    u32 offset;                 /* data begins at buf + offset */
    refcount refcount;          /* reference held for source (e.g. page) */
} *sg_buf;

/* represents a scatter-gather transaction - global kernel object */
typedef struct sg_list {
    buffer b;                   /* buffer (array) of sg_bufs */
    word count;                 /* total bytes accumulated */
    struct list l;              /* for free list */
} *sg_list;

typedef closure_type(sg_io, void, sg_list, range, status_handler);

static inline sg_buf sg_list_tail_add(sg_list sg, word length)
{
    buffer_extend(sg->b, sizeof(struct sg_buf));
    void *sgb = buffer_ref(sg->b, buffer_length(sg->b));
    buffer_produce(sg->b, sizeof(struct sg_buf));
    fetch_and_add(&sg->count, length);
    return sgb;
}

/* Once an sg_buf is removed from the list, it must be later released
   with sg_buf_release. Unremoved items from the list can be released
   at once with sg_list_finish. */

static inline sg_buf sg_list_head_peek(sg_list sg)
{
    if (buffer_length(sg->b) < sizeof(struct sg_buf))
        return INVALID_ADDRESS;
    return (sg_buf)buffer_ref(sg->b, 0);
}

static inline sg_buf sg_list_head_remove(sg_list sg)
{
    if (buffer_length(sg->b) < sizeof(struct sg_buf))
        return INVALID_ADDRESS;
    sg_buf sgb = (sg_buf)buffer_ref(sg->b, 0);
    fetch_and_add(&sg->count, -sgb->size);
    buffer_consume(sg->b, sizeof(struct sg_buf));
    return sgb;
}

static inline void sg_buf_release(sg_buf sgb)
{
    if (sgb->refcount)
        refcount_release(sgb->refcount);
}

static inline void sg_list_release(sg_list sg)
{
    sg_buf sgb;
    while ((sgb = sg_list_head_remove(sg)) != INVALID_ADDRESS) {
        sg_buf_release(sgb);
    }
}

sg_list allocate_sg_list(void);
void deallocate_sg_list(sg_list sg);
void init_sg(heap h);
u64 sg_copy_to_buf(void *target, sg_list sg, u64 length);
u64 sg_copy_to_buf_and_release(void *dest, sg_list src, u64 limit);
u64 sg_move(sg_list dest, sg_list src, u64 n);
u64 sg_zero_fill(sg_list sg, u64 n);
sg_io sg_wrapped_block_reader(block_io bio, int block_order, heap backed);
