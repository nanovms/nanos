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

typedef struct sg_chunk {
    struct list l;              /* for free list */
    u32 start;
    u32 end;
    struct sg_chunk *next;
    struct sg_buf bufs[];
} *sg_chunk;

/* represents a scatter-gather transaction - global kernel object */
typedef struct sg_list {
    sg_chunk head;
    sg_chunk tail;
    word count;                 /* total bytes accumulated */
    struct list l;              /* for free list */
} *sg_list;

typedef closure_type(sg_io, void, sg_list, range, status_handler);

sg_buf sg_list_tail_add(sg_list sg, word length);

/* Once an sg_buf is removed from the list, it must be later released
   with sg_buf_release. Unremoved items from the list can be released
   at once with sg_list_finish. */

static inline sg_buf sg_list_peek_at(sg_list sg, u64 index)
{
    sg_chunk c = sg->head;
    u64 offset = index * sizeof(struct sg_buf);
    while (c) {
        if (c->start + offset < c->end)
            return ((void *)c + c->start + offset);
        offset -= c->end - c->start;
        c = c->next;
    }
    return INVALID_ADDRESS;
}

static inline sg_buf sg_list_head_peek(sg_list sg)
{
    sg_chunk head = sg->head;
    if (!head || (head->start == head->end))
        return INVALID_ADDRESS;
    return ((void *)head + head->start);
}

sg_buf sg_list_head_remove(sg_list sg);

#define sg_list_length(sg)  (buffer_length((sg)->b) / sizeof(struct sg_buf))

typedef closure_type(sg_list_handler, boolean, sg_buf);

/* sg bufs cannot be removed from the list while iterating the list */
static inline void sg_list_iterate(sg_list sg, sg_list_handler h)
{
    sg_chunk c = sg->head;
    while (c) {
        for (u32 offset = c->start; offset < c->end; offset += sizeof(struct sg_buf))
            if (!apply(h, (void *)c + offset))
                return;
        c = c->next;
    }
}

static inline u32 sg_buf_len(sg_buf sgb)
{
    return sgb->size - sgb->offset;
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
void sg_consume(sg_list sg, u64 length);
u64 sg_copy_to_buf(void *target, sg_list sg, u64 length);
u64 sg_copy_to_buf_and_release(void *dest, sg_list src, u64 limit);
u64 sg_move(sg_list dest, sg_list src, u64 n);
u64 sg_zero_fill(sg_list sg, u64 n);
sg_io sg_wrapped_block_reader(block_io bio, int block_order, heap backed);

#ifdef KERNEL
boolean sg_fault_in(sg_list sg, u64 n);
#else
#define sg_fault_in(sg, n)  true
#endif
