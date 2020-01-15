#include <runtime.h>
#include <x86_64.h>

/* TODO:
   - queue paranoia mode
   - fix kernel headers in general (shouldn't need arch-specific include above)
*/

typedef struct queue {
    volatile union {
        struct {
            u32 prod_head;
            u32 cons_tail;
        };
        u64 prod_combined;
    };
    volatile union {
        struct {
            u32 cons_head;
            u32 prod_tail;
        };
        u64 cons_combined;
    };
    void ** d;
    heap h;
    int order;
} *queue;

#define _queue_size(q) (1ul << (q)->order)
#define _queue_idx(q, i) ((i) & MASK((q)->order))
#define _queue_assert(x) assert(x)
#define _queue_pause kern_pause

/* little endian */
#define _head_from_combined(c) ((u32)((c) & MASK(32)))
#define _tail_from_combined(c) ((u32)((c) >> 32))

static inline boolean _enqueue_common(queue q, void *p, boolean multi)
{
    if (p == INVALID_ADDRESS)
        return false;

    u32 head, next, tail, size = _queue_size(q);
    u64 pc;

  retry:
    pc = q->prod_combined;
    head = _head_from_combined(pc); /* prod_head */
    tail = _tail_from_combined(pc); /* cons_tail */
    if (head - tail == size)
        return false; /* full */
    _queue_assert(head - tail < size);
    next = head + 1;
    if (multi) {
        if (!__sync_bool_compare_and_swap(&q->prod_head, head, next))
            goto retry;
    } else {
        q->prod_head = next;
    }

    /* save data */
    q->d[_queue_idx(q, head)] = p;
    write_barrier();

    /* multi-producer: wait for previous enqueues to commit */
    if (multi) {
        while (q->prod_tail != head)
            _queue_pause();
    }

    /* commit */
    q->prod_tail = next;
    return true;
}

static inline void * _dequeue_common(queue q, boolean multi)
{
    u32 head, next, tail, size = _queue_size(q);
    u64 cc;

  retry:
    cc = q->cons_combined;
    head = _head_from_combined(cc); /* cons_head */
    tail = _tail_from_combined(cc); /* prod_tail */

    if (head == tail)
        return INVALID_ADDRESS; /* empty */
    _queue_assert(tail - head <= size);
    next = head + 1;
    if (multi) {
        if (!__sync_bool_compare_and_swap(&q->cons_head, head, next))
            goto retry;
    } else {
        q->cons_head = next;
    }

    /* retrieve data */
    void *p = q->d[_queue_idx(q, head)];
    read_barrier();

    /* multi-consumer: wait for previous dequeues to commit */
    if (multi) {
        while (q->cons_tail != head)
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
