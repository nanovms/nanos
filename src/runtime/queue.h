#include <runtime.h>
#include <x86_64.h>

/* TODO:
   - add paranoia build define
   - fix kernel headers in general (shouldn't need arch-specific include above)
*/

typedef struct queue {
    volatile u64 prod_head;
    volatile u64 prod_tail;
    volatile u64 cons_head;
    volatile u64 cons_tail;
    void ** d;
    int order;
    int pad0;
    heap h;
    u64 pad1;                   /* cacheline-sized */
} *queue;

#define _queue_size(q) U64_FROM_BIT(q->order)
#define _queue_idx(q, i) ((i) & MASK(q->order))
#define _queue_assert(x) assert(x)
#define _queue_pause kern_pause

static inline boolean _enqueue_common(queue q, void *p, boolean multi)
{
    u64 head, next, tail;

    /* reserve producer slot */
    do {
        head = q->prod_head;
        tail = q->cons_tail;
        next = head + 1;
        if ((head - tail) == _queue_size(q))
            return false; /* full */
        _queue_assert(head - tail < _queue_size(q));
    } while (!__sync_bool_compare_and_swap(&q->prod_head, head, next));

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
    u64 head, next, tail;

    /* reserve consumer slot */
    do {
        head = q->cons_head;
        tail = q->prod_tail;
        next = head + 1;
        if (head == tail)
            return INVALID_ADDRESS; /* empty */
        _queue_assert(head - tail > 0);
    } while (!__sync_bool_compare_and_swap(&q->cons_head, head, next));

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

#define _queue_data_size(o) ((1ull << (o)) * sizeof(void *))
#define _queue_alloc_size(o) (sizeof(struct queue) + _queue_data_size(o))

static inline void queue_init(queue q, int order, void ** buf)
{
    q->prod_head = 0;
    q->prod_tail = 0;
    q->cons_head = 0;
    q->cons_tail = 0;
    q->order = order;
    q->d = buf;
    q->h = 0;
    zero(buf, _queue_data_size(order));
    write_barrier();
}

/* will round up size to next power-of-2 */
queue allocate_queue(heap h, u64 size);

void deallocate_queue(queue q);
