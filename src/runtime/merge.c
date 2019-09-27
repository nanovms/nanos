#include <runtime.h>

typedef closure_type(merge_apply, status_handler);

struct merge {
   heap h;
   word count;
   merge_apply apply;
   status_handler completion;
   status last_status;
};

closure_function(1, 1, void, merge_join,
                 merge, m,
                 status, s)
{
    merge m = bound(m);
    if (s != STATUS_OK)
        m->last_status = s; // last failed status

    word n = fetch_and_add(&m->count, (word)-1);
    if (n == 1) {
        apply(m->completion, m->last_status);
        deallocate(m->h, m, sizeof(struct merge));
    }
}

closure_function(2, 0, status_handler, merge_add,
                 merge, m, status_handler, sh)
{
    fetch_and_add(&bound(m)->count, 1);
    return bound(sh);
}

merge allocate_merge(heap h, status_handler completion)
{
    merge m = allocate_zero(h, sizeof(struct merge));
    m->h = h;
    status_handler sh = closure(h, merge_join, m);
    m->apply = closure(h, merge_add, m, sh);
    m->completion = completion;
    m->last_status = STATUS_OK;
    return m;
}

status_handler apply_merge(merge m)
{
    return apply(m->apply);
}
