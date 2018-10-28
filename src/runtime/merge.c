#include <runtime.h>

// should combine status 
static CLOSURE_2_1(finish, void, status_handler, word*, status);
static void finish(status_handler c, word *count, status s)
{

    u64 n = fetch_and_add(count, (word)-1);
    if (n == 1) apply(c, 0);
}

static CLOSURE_2_0(merge_join, status_handler, status_handler, word *);
static status_handler merge_join(status_handler m, word *count)
{
    word n = fetch_and_add(count, 1);
    return m;
}

merge allocate_merge(heap h, status_handler c)
{
    word *count = allocate_zero(h, sizeof(word));
    status_handler f = closure(h, finish, c, count);
    return closure(h, merge_join, f, count);
}
