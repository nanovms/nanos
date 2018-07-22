#include <tfs_internal.h>

// should combine status 
static CLOSURE_2_1(finish, void, status_handler, u64*, status);
static void finish(status_handler c, u64 *count, status s)
{
    rprintf("merge finish\n");
    u64 n = fetch_and_add(count, -1ull);
    if (n == 1) apply(c, 0);
}

static CLOSURE_2_0(merge_join, status_handler, status_handler, u64 *);
static status_handler merge_join(status_handler m, u64 *count)
{
    u64 n = fetch_and_add(count, +1ull);
    rprintf ("merge join\n");
    return m;
}

merge allocate_merge(heap h, status_handler c)
{
    u64 *count = allocate_zero(h, sizeof(u64));
    status_handler m = closure(h, finish, c, count);
    apply(m, 0);
    return closure(h, merge_join, m, count);
}
