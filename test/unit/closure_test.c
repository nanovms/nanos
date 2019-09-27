#include <runtime.h>
#include <stdlib.h>

#define TEST_L -1ull
#define TEST_R -5ull
#define TEST_RV 3

closure_function(1, 1, u64, test0,
                 u64, l,
                 u64, r)
{
    if (bound(l) != TEST_L || r != TEST_R) {
        msg_err("argument mismatch\n");
        exit(EXIT_FAILURE);
    }
    closure_finish();
    return TEST_RV;
}

static boolean terminate_reached;

closure_function(0, 2, void, test1,
                 void *, self, boolean, terminate)
{
    if (terminate) {
        terminate_reached = true;
        return;
    }
    if (closure_self() != self) {
        msg_err("self mismatch: %p, %p, terminate %d\n", closure_self(), self, terminate);
        exit(EXIT_FAILURE);
    }
    apply(closure_self(), self, true);
}

typedef closure_type(test0_type, u64, u64);
typedef closure_type(test1_type, void, void *, boolean);

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    u64 heap_occupancy = h->allocated;
    test0_type f = closure(h, test0, TEST_L);
    if (apply(f, TEST_R) != TEST_RV) {
        msg_err("return value mismatch\n");
        return EXIT_FAILURE;
    }
    if (h->allocated > heap_occupancy) {
        msg_err("leak after closure_finish(): prev %ld, now %ld\n",
                heap_occupancy, h->allocated);
        return EXIT_FAILURE;
    }
    heap_occupancy = h->allocated;
    test1_type t = closure(h, test1);
    apply(t, t, false);
    deallocate_closure(t);
    if (h->allocated > heap_occupancy) {
        msg_err("leak after deallocate_closure(): prev %ld, now %ld\n",
                heap_occupancy, h->allocated);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
