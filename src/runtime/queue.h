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

static inline boolean _enqueue_common(queue q, void *p, boolean multi, int n)
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
    next = pc.head + n;
    if (multi) {
        if (!compare_and_swap_32((u32*)&q->prod_head, pc.head, next))
            goto retry;
    } else {
        q->prod_head = next;
    }

    /* p is value if single word, else buffer pointer */
    // XXX check asm for inlining
    void **dest = &q->d[_queue_idx(q, pc.head)];
    if (n == 1)
        *dest = p;
    else
        runtime_memcpy(dest, p, sizeof(u64) * n);
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

static inline void _dequeue_common(queue q, void **p, boolean multi, int n)
{
    u32 next, size = _queue_size(q);
    union combined cc;
    _queue_assert(n > 0 && (n & (n - 1)) == 0);

  retry:
    cc.w = q->cc.w;               /* cons_head, prod_tail */

    if (cc.head == cc.tail) {
        *p = INVALID_ADDRESS;   /* empty */
        return;
    }
    _queue_assert(cc.tail - cc.head <= size);
    next = cc.head + n;
    if (multi) {
        if (!compare_and_swap_32((u32*)&q->cons_head, cc.head, next))
            goto retry;
    } else {
        q->cons_head = next;
    }

    /* retrieve data */
    // XXX check asm for inlining
    void **src = &q->d[_queue_idx(q, cc.head)];
    if (n == 1)
        *p = *src;
    else
        runtime_memcpy(p, src, sizeof(u64) * n);
    read_barrier();

    /* multi-consumer: wait for previous dequeues to commit */
    if (multi) {
        while (q->cons_tail != cc.head)
            _queue_pause();
    }

    /* commit */
    q->cons_tail = next;
}

/* multi-producer by default */
static inline boolean enqueue(queue q, void *p)
{
    return _enqueue_common(q, p, true, 1);
}

static inline boolean enqueue_single(queue q, void *p)
{
    return _enqueue_common(q, p, false, 1);
}

static inline void *dequeue(queue q)
{
    void *p;
    _dequeue_common(q, &p, true, 1);
    return p;
}

static inline void *dequeue_single(queue q)
{
    void *p;
    _dequeue_common(q, &p, false, 1);
    return p;
}

/* These are variants which take a unit size expressed in log2 of words.
   Only use one size for a given queue. */
static inline boolean enqueue_n(queue q, void *p, int n)
{
    _queue_assert(n > 1 && (n & (n - 1)) == 0);
    return _enqueue_common(q, p, true, n);
}

static inline boolean enqueue_n_single(queue q, void *p, int n)
{
    _queue_assert(n > 1 && (n & (n - 1)) == 0);
    return _enqueue_common(q, p, false, n);
}

static inline boolean dequeue_n(queue q, void **p, int n)
{
    _queue_assert(n > 1 && (n & (n - 1)) == 0);
    _dequeue_common(q, p, true, n);
    return *p != INVALID_ADDRESS;
}

static inline boolean dequeue_n_single(queue q, void **p, int n)
{
    _queue_assert(n > 1 && (n & (n - 1)) == 0);
    _dequeue_common(q, p, false, n);
    return *p != INVALID_ADDRESS;
}

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

static inline void *queue_peek_at(queue q, u32 idx)
{
    if (q->prod_tail > q->cons_head + idx)
        return q->d[_queue_idx(q, q->cons_head + idx)];
    else
        return INVALID_ADDRESS;
}

/* only safe with lock - can we dispose of this? */
static inline void *queue_peek(queue q)
{
    return queue_peek_at(q, 0);
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
