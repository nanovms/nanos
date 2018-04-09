#include <sruntime.h>

// there is a test-and-set atomic resize for the multiprocessor case?

struct queue {
    // these should be on cache lines in the mp case
    u64 read, write, length;
    void *body[];
};

void enqueue(queue q, thunk n)
{
    if (((q->write + 1)  & MASK(q->length))  == (q->read & MASK(q->length))) {
        halt("queue overrun");
    }
    // fix this race for multiple writers...maybe a lookaside region
    // next to the write pointer so we can use cas128?
    u64 f = read_flags();
    disable_interrupts();
    u64 slot = fetch_and_add(&q->write, 1);
    q->body[slot & MASK(q->length)]= n;
    rprintf("enqueue %d %d\n", q->read, q->write);
    if (f & FLAG_INTERRUPT) enable_interrupts();    
}

thunk dequeue(queue q)
{
    if ((q->read & MASK(q->length)) == (q->write & MASK(q->length))) 
        return 0;

    // this isn't necessary given single reader, but it also has
    // the barrier
    u64 slot = fetch_and_add(&q->read, 1);
    return q->body[slot];
}


queue allocate_queue(heap h, u64 size)
{
    queue q = allocate(h, sizeof(struct queue) + size*sizeof(void *));
    q->length = size; // log
    q->write = q->read = 0;
    return q;
}

