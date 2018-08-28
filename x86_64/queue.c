#include <runtime.h>

// there is a test-and-set atomic resize for the multiprocessor case?
// this is not in x86_64


void enqueue(queue q, void *n)
{
    u64 mask = q->length -1;
    if (((q->write + 1)  & mask)  == (q->read & mask)) {
        halt("queue overrun");
    }
    // fix this race for multiple writers...maybe a lookaside region
    // next to the write pointer so we can use cas128?
    u64 f = read_flags();
    disable_interrupts();
    u64 slot = fetch_and_add(&q->write, 1);
    q->body[slot & mask]= n;
    if (f & FLAG_INTERRUPT) enable_interrupts();    
}

int queue_length(queue q)
{
    return q->write - q->read;
}

void *queue_peek(queue q)
{
    u64 mask = q->length -1;
    if ((q->read & mask) == (q->write & mask) )
        return 0;
    return q->body[q->read&mask];
}

void *dequeue(queue q)
{
    u64 mask = q->length -1;
    if ((q->write & mask) == (q->read & mask) )
        return 0;
    
    // this isn't necessary given single reader, but it also has
    // the barrier
    u64 slot = fetch_and_add(&q->read, 1);
    return q->body[slot&mask];
}


// has to be power two
queue allocate_queue(heap h, u64 size)
{
    queue q = allocate(h, sizeof(struct queue) + size * sizeof(void *));
    q->length = size; // log
    q->write = q->read = 0;
    q->h = h;
    return q;
}

void deallocate_queue(queue q, u64 size)
{
    deallocate(q->h, q, sizeof(struct queue) + size * sizeof(void *));
}
