#include <runtime.h>
#include <x86_64.h>

/* TODO:
   - add paranoia build define
   - fix kernel headers in general (shouldn't need arch-specific include above)
   - It might be possible to join prod_head and cons_tail into a
     128-bit CAS if the architecture (and compiler) supports it. This
     could resolve some of the transient queue full conditions noted
     below.
*/

#define QUEUE_FULL_RETRIES 3    /* move this */

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
    if (p == INVALID_ADDRESS)
        return false;

    u64 head, next, tail, size = _queue_size(q);
    int retries = QUEUE_FULL_RETRIES;

  retry:
    /* Enforce ordering here so that any interrupt, simultaneous
       update or context switch (if in userspace) between the head
       and tail reads could only result in an overestimate of the
       queue length. */
    tail = q->cons_tail;
    read_barrier();

    if (multi) {
        /* If we're multi-producer and the delta exceeds the queue
           size, it's a dead giveaway that the head advanced since the
           tail read, so retry unconditionally. */
        head = q->prod_head;
        if (head - tail > size)
            goto retry;
    } else {
        /* no reserve/commit in single variant; just ignore prod_head */
        head = q->prod_tail;
        _queue_assert(head - tail <= size);
    }

    /* For either a single or multi-producer enqueue, if the delta
       is exactly the queue size, there's a chance that tail
       advanced since the head read and that the queue isn't
       actually full, so retry there too (but only up to some
       limit so that we don't spin unnecessarily on queue full).

       This means that there's some very small chance that an
       enqueue can fail when there is a free slot that could be
       reserved. Either take the possibility of this transient
       condition into account (likely the same remedy as for a
       true queue full condition) or place a lock around queue
       access. */
    if (head - tail == size) {
        if (retries-- > 0)
            goto retry;
        return false; /* full */
    }
    next = head + 1;

    /* multi-producer: CAS on prod_head in an attempt to reserve a
       slot in the queue. Note that this will catch any queue full
       condition that may arise since previously reading head. */
    if (multi && !__sync_bool_compare_and_swap(&q->prod_head, head, next))
        goto retry;

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

  retry:
    /* Enforce read ordering here so that we don't falsely detect
       queue empty or see the consumer head pass the producer tail.

       As with enqueue, ignore cons_head if we're single-consumer.
    */
    head = q->cons_head;
    read_barrier();
    tail = q->prod_tail;
    if (head == tail)
        return INVALID_ADDRESS; /* empty */
    _queue_assert(tail - head > 0);
    next = head + 1;

    /* multi-producer: CAS on cons_head to reserve a slot to
       consume. This also covers any queue empty condition that may
       have arisen since the previous check. */
    if (multi && !__sync_bool_compare_and_swap(&q->cons_head, head, next))
        goto retry;

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

    /* single-producer: Though we don't need cons_head for the
       dequeue, it is used in other functions to track queue length,
       and they can't know which variant of dequeue is being used. So
       keep a copy in cons_head too. */
    if (!multi)
        q->cons_head = next;
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
