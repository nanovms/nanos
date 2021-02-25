/* TODO:
   - queue paranoia mode
   - fix kernel headers in general (shouldn't need arch-specific include above)
*/

union combined {
    struct {
        u32 head;
        u32 tail;
    };
    u64 w;
};

typedef struct queue {
    volatile union combined pc; /* prod_head, cons_tail */
    volatile union combined cc; /* cons_head, prod_tail */
    void ** d;
    heap h;
    int order;
} *queue;

#define prod_head pc.head
#define prod_tail cc.tail
#define cons_head cc.head
#define cons_tail pc.tail

#define _queue_size(q) (1ul << (q)->order)
#define _queue_idx(q, i) ((i) & MASK((q)->order))
#define _queue_assert(x) assert(x)
#define _queue_pause kern_pause

static inline boolean _enqueue_common(queue q, void *p, boolean multi)
{
    if (p == INVALID_ADDRESS)
        return false;

    u32 next, size = _queue_size(q);
    union combined pc;

  retry:
    pc.w = q->pc.w;               /* prod_head, cons_tail */
    if (pc.head - pc.tail == size)
        return false; /* full */
    _queue_assert(pc.head - pc.tail < size);
    next = pc.head + 1;
    if (multi) {
        if (!compare_and_swap_32((u32*)&q->prod_head, pc.head, next))
            goto retry;
    } else {
        q->prod_head = next;
    }

    /* save data */
    q->d[_queue_idx(q, pc.head)] = p;
    write_barrier();

    /* multi-producer: wait for previous enqueues to commit */
    if (multi) {
        while (q->prod_tail != pc.head)
            _queue_pause();
    }

    /* commit */
    q->prod_tail = next;
    return true;
}

static inline void * _dequeue_common(queue q, boolean multi)
{
    u32 next, size = _queue_size(q);
    union combined cc;

  retry:
    cc.w = q->cc.w;               /* cons_head, prod_tail */

    if (cc.head == cc.tail)
        return INVALID_ADDRESS; /* empty */
    _queue_assert(cc.tail - cc.head <= size);
    next = cc.head + 1;
    if (multi) {
        if (!compare_and_swap_32((u32*)&q->cons_head, cc.head, next))
            goto retry;
    } else {
        q->cons_head = next;
    }

    /* retrieve data */
    void *p = q->d[_queue_idx(q, cc.head)];
    read_barrier();

    /* multi-consumer: wait for previous dequeues to commit */
    if (multi) {
        while (q->cons_tail != cc.head)
            _queue_pause();
    }

    /* commit */
    q->cons_tail = next;
    return p;
}

/* multi-producer by default */
static inline boolean enqueue(queue q, void *p)
{
    return _enqueue_common(q, p, true);
}

static inline boolean enqueue_single(queue q, void *p)
{
    return _enqueue_common(q, p, false);
}

static inline void *dequeue(queue q)
{
    return _dequeue_common(q, true);
}

static inline void *dequeue_single(queue q)
{
    return _dequeue_common(q, false);
}

/* results for these are clearly transient without a lock on q */
static inline u64 queue_length(queue q)
{
    return q->prod_tail - q->cons_head;
}

static inline boolean queue_empty(queue q)
{
    return q->prod_tail == q->cons_head;
}

static inline boolean queue_full(queue q)
{
    return q->prod_tail - q->cons_head == _queue_size(q);
}

/* only safe with lock - can we dispose of this? */
static inline void *queue_peek(queue q)
{
    return q->prod_tail > q->cons_head ? q->d[_queue_idx(q, q->cons_head)] : INVALID_ADDRESS;
}

#define queue_data_size(order) ((1ull << (order)) * sizeof(void *))

static inline void queue_init(queue q, int order, void ** buf)
{
    q->prod_head = 0;
    q->prod_tail = 0;
    q->cons_head = 0;
    q->cons_tail = 0;
    q->order = order;
    q->d = buf;
    q->h = 0;
    zero(buf, queue_data_size(order));
    write_barrier();
}

/* will round up size to next power-of-2 */
queue allocate_queue(heap h, u64 size);

void deallocate_queue(queue q);
