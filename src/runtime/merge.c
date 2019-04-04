#include <runtime.h>

typedef closure_type(merge_apply, status_handler);

struct merge {
   heap h;
   word count;
   merge_apply apply;
   status_handler completion;
   status last_status;
};

static CLOSURE_1_1(merge_join, void, merge, status);
static void merge_join(merge m, status s)
{
    if (s != STATUS_OK)
        m->last_status = s; // last failed status

    word n = fetch_and_add(&m->count, (word)-1);
    if (n == 1) {
        apply(m->completion, m->last_status);
        deallocate(m->h, m, sizeof(struct merge));
    }
}

static CLOSURE_2_0(merge_add, status_handler, merge, status_handler);
static status_handler merge_add(merge m, status_handler sh)
{
    fetch_and_add(&m->count, 1);
    return sh;
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
