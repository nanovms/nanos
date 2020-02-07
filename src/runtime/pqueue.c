#include <runtime.h>

typedef u32 index; //indices are off by 1 from vector references

struct pqueue {
    heap h;
    vector body;
    boolean (*sort)(void *, void *);
};

static inline void swap(pqueue q, index x, index y)
{
    void *temp = vector_get(q->body, x-1);
    vector_set(q->body, x-1, vector_get(q->body, y-1));
    vector_set(q->body, y-1, temp);
}

#define qcompare(__q, __x, __y)\
  (q->sort(vector_get((__q)->body, (__x-1)), \
                vector_get((__q)->body, (__y-1))))

static void heal(pqueue q, index where)
{
    index last = vector_length(q->body);
    index i;
    while ((i = where << 1) <= last) {
        if (i < last && qcompare(q, i, i+1))
            i++;                /* right is larger */
        if (!qcompare(q, where, i))
            return;
        swap(q, where, i);
        where = i;
    }
}

static void add_pqueue(pqueue q, index i)
{
    index parent = i >> 1;

    while ((parent > 0) && qcompare(q, parent, i)) {
        swap(q, i, parent);
        i = parent;
        parent >>= 1;
    }
}

void pqueue_insert(pqueue q, void *v)
{
    vector_push(q->body, v);
    add_pqueue(q, vector_length(q->body));
}

void *pqueue_pop(pqueue q)
{
    void *result = INVALID_ADDRESS;

    if (vector_length(q->body) > 0) {
        result = vector_get(q->body, 0);
        void *n = vector_pop(q->body);
        if (vector_peek(q->body)){
            vector_set(q->body, 0, n);
            heal(q, 1);
        }
    }
    return result;
}

void *pqueue_peek(pqueue q)
{
    if (vector_length(q->body)) return(vector_get(q->body, 0));
    return INVALID_ADDRESS;
}

pqueue allocate_pqueue(heap h, boolean(*sort)(void *, void *))
{
    pqueue p = allocate(h, sizeof(struct pqueue));
    p->h = h;
    p->body = allocate_vector(h, 10);
    p->sort = sort;
    return(p);
}

void deallocate_pqueue(pqueue p)
{
    assert(p);
    deallocate_vector(p->body);
    deallocate(p->h, p, sizeof(struct pqueue));
}
