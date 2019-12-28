#include <runtime.h>

methods tagmethods[tag_max];

static inline CLOSURE_3_3(iterator_each, void, value *, value *, thunk *,
                   value, value, thunk);


void iterator_each(value *pk, value *pv, thunk *pnext, 
                   value k, value v, thunk next)
{
    *pk = k;
    *pv = v;
    *pnext = next;
}

each close_each_copy(heap h, value *k, value *v, thunk *t)
{
    return closure(h, iterator_each, k, v, t);
}

