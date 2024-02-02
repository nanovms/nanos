#include <runtime.h>

#include "../test_utils.h"

#define TEST_L -1ull
#define TEST_R -5ull
#define TEST_RV 3

closure_function(1, 1, u64, test0,
                 u64, l,
                 u64, r)
{
    if (bound(l) != TEST_L || r != TEST_R) {
        test_error("argument mismatch");
    }
    closure_finish();
    return TEST_RV;
}

static boolean terminate_reached;

closure_function(1, 2, void, test1,
                 int, count,
                 void *, self, boolean, terminate)
{
    if (terminate) {
        if (bound(count) != 1) {
            test_error("bound variable value mismatch");
        }
        terminate_reached = true;
        return;
    }
    if (closure_self() != self) {
        test_error("self mismatch: %p, %p, terminate %d", closure_self(), self, terminate);
    }
    bound(count)++;
    apply(closure_self(), self, true);
}

typedef closure_type(test0_type, u64, u64);
typedef closure_type(test1_type, void, void *, boolean);

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    u64 heap_occupancy = heap_allocated(h);
    test0_type f = closure(h, test0, TEST_L);
    if (apply(f, TEST_R) != TEST_RV) {
        test_error("return value mismatch");
    }
    if (heap_allocated(h) > heap_occupancy) {
        test_error("leak after closure_finish(): prev %lld, now %lld",
                heap_occupancy, heap_allocated(h));
    }
    heap_occupancy = heap_allocated(h);
    test1_type t = closure(h, test1, 0);
    apply(t, t, false);
    deallocate_closure(t);
    if (heap_allocated(h) > heap_occupancy) {
        test_error("leak after deallocate_closure(): prev %lld, now %lld",
                heap_occupancy, heap_allocated(h));
    }
    return EXIT_SUCCESS;
}
