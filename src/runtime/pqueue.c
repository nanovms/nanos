#include <runtime.h>

//#define PQUEUE_PARANOIA

typedef u32 index; //indices are off by 1 from vector references

struct pqueue {
    heap h;
    vector body;
    boolean (*sort)(void *, void *);
};

static inline void swap(pqueue q, index x, index y)
{
    void *temp = vector_get(q->body, x-1);
    assert(vector_set(q->body, x-1, vector_get(q->body, y-1)));
    assert(vector_set(q->body, y-1, temp));
}

#define qcompare(__q, __x, __y)\
    (q->sort(vector_get((__q)->body, ((__x)-1)),        \
             vector_get((__q)->body, ((__y)-1))))

static void heal_down(pqueue q, index where)
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

static void heal_up(pqueue q, index where)
{
    while (where > 1 && qcompare(q, where >> 1, where)) {
        swap(q, where >> 1, where);
        where >>= 1;
    }
}

#ifdef PQUEUE_PARANOIA
boolean pqueue_validate(pqueue q, index x)
{
    index last = vector_length(q->body);
    index i = x << 1;
    if (i > last)
        return true;
    if ((i < last && qcompare(q, x, i + 1)) ||
        qcompare(q, x, i))
        return false;
    return pqueue_validate(q, i) && (i == last || pqueue_validate(q, i + 1));
}
#endif

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
#ifdef PQUEUE_PARANOIA
    assert(pqueue_validate(q, 1));
#endif
}

boolean pqueue_remove(pqueue q, void *v)
{
    index i;
    for (i = 0; i < vector_length(q->body); i++) {
        void *e = vector_get(q->body, i);
        if (e == v) {
            pqueue_remove_at(q, i);
            return true;
        }
    }
    return false;
}

void pqueue_remove_at(pqueue q, u32 i)
{
    vector body = q->body;
    void *n = vector_pop(body);
    if (i != vector_length(body)) {
        index idx = i + 1;
        assert(vector_set(body, i, n));
        if (idx > 1 && qcompare(q, idx >> 1, idx))
            heal_up(q, i + 1);
        else
            heal_down(q, i + 1);
    }
#ifdef PQUEUE_PARANOIA
    assert(pqueue_validate(q, 1));
#endif
}

void *pqueue_pop(pqueue q)
{
    void *result = INVALID_ADDRESS;

    if (vector_length(q->body) > 0) {
        result = vector_get(q->body, 0);
        void *n = vector_pop(q->body);
        if (vector_peek(q->body)){
            assert(vector_set(q->body, 0, n));
            heal_down(q, 1);
        }
    }
#ifdef PQUEUE_PARANOIA
    assert(pqueue_validate(q, 1));
#endif
    return result;
}

void *pqueue_peek(pqueue q)
{
    return pqueue_peek_at(q, 0);
}

void *pqueue_peek_at(pqueue q, u32 i)
{
    vector body = q->body;
    if (vector_length(body) > i)
        return vector_get(body, i);
    return INVALID_ADDRESS;
}

u64 pqueue_length(pqueue q)
{
    return vector_length(q->body);
}

void pqueue_reorder(pqueue q)
{
    /* Floyd's heap construction algorithm */
    for (index i = vector_length(q->body) / 2; i > 0; i--)
        heal_down(q, i);
#ifdef PQUEUE_PARANOIA
    assert(pqueue_validate(q, 1));
#endif
}

boolean pqueue_walk(pqueue q, pqueue_element_handler h)
{
    void *e;
    vector_foreach(q->body, e)
        if (!apply(h, e))
            return false;
    return true;
}

pqueue allocate_pqueue(heap h, boolean(*sort)(void *, void *))
{
    pqueue p = allocate(h, sizeof(struct pqueue));
    assert(p != INVALID_ADDRESS);
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
