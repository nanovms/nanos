#include <runtime.h>

#define _queue_buf_offset    pad(sizeof(struct queue), DEFAULT_CACHELINE_SIZE)
#define _queue_alloc_size(o) (_queue_buf_offset + queue_data_size(o))

/* will round up size to next power-of-2 */
queue allocate_queue(heap h, u64 size)
{
    if (size == 0)
        return INVALID_ADDRESS;
    int order = find_order(size);
    queue q = allocate(h, _queue_alloc_size(order));
    if (q == INVALID_ADDRESS)
        return q;
    void *buf = ((void *)q) + _queue_buf_offset;
    queue_init(q, order, buf);
    q->h = h;
    return q;
}

void deallocate_queue(queue q)
{
    if (q->h)
        deallocate(q->h, q, _queue_alloc_size(q->order));
}
