#include <runtime.h>

void queue_dump(queue q)
{
    rprintf("queue @ %p being dumped\n", q);
    rprintf("queue size: %p\n", q->size);
    rprintf("queue count: %p\n", q->count);
    for (int i = 0; i < q->size; i ++) {
        if (i >= q->read % q->size && i < q->write % q->size) {
            rprintf("+ ");
        } else {
            rprintf("- ");
        }

        rprintf("%p: ", i);
        rprintf("%p\n", q->buf[i]);
    }
}

boolean enqueue(queue q, void *n)
{
    u64 count = fetch_and_add(&q->count, 1);
    u64 write;
    boolean r;

    if (count >= q->size) {
        // can't enqueue more elements than the bounds
        fetch_and_add(&q->count, -1);
        return false;
    }

    // rusty 'acquire the ownership' of the next element in the queue
    write = fetch_and_add(&q->write, 1);

    // put the data in the buf
    r = __sync_bool_compare_and_swap(&q->buf[write % q->size], 0, n);
    if (!r) {
        // should never happen
        // if it does, then something went horribly wrong.
        queue_dump(q);
        halt("queue is in inconsistent state");
    }

    // otherwise we are done
    return true;
}

int queue_length(queue q)
{
    return __atomic_load_n(&q->count, __ATOMIC_ACQUIRE);
}

void *queue_peek(queue q)
{
    if (__atomic_load_n(&q->count, __ATOMIC_ACQUIRE) == 0)
        return 0;

    return __atomic_load_n(&q->buf[q->read % q->size], __ATOMIC_ACQUIRE);
}

#define DEQUEUE_MAX_BACKOFF 10000
void *dequeue(queue q)
{
    int backoff = 1;
    int i;
    void *r;

    if (__atomic_load_n(&q->count, __ATOMIC_ACQUIRE) == 0)
        return 0;

retry:
    r = __atomic_exchange_n(&q->buf[q->read ++ % q->size], 0, __ATOMIC_ACQUIRE);
    if (!r) {
        // if we had already backed off that maximum, let the dequeueing fail
        if (backoff >= DEQUEUE_MAX_BACKOFF)
            return false;

        // issue @backoff PAUSE instructions
        for (i = 0; i < backoff; i ++) {
            // make sure the compiler does not optimize away the
            asm volatile("pause");
        }

        // exponentially increase the amount of PAUSE instructions executed
        backoff *= 10;
        goto retry;
    }

    // formally tell tell the queue that the element is gone
    fetch_and_add(&q->count, -1);
    return r;
}

queue allocate_queue(heap h, u64 size)
{
    queue q = allocate(h, sizeof(struct queue) + size * sizeof(void *));
    q->size = size;
    q->count = 0;
    q->write = q->read = 0;
    q->h = h;
    zero(q->buf, size * sizeof(void *));
    // XXX: we could do a release ordering here, however let's just use a full
    // barrier for now.
    memory_fence();
    return q;
}

void deallocate_queue(queue q, u64 size)
{
    deallocate(q->h, q, sizeof(struct queue) + size * sizeof(void *));
}
