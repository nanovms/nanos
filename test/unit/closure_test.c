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

closure_function(1, 2, void, test1,
                 int, count,
                 void *, self, boolean, terminate)
{
    if (terminate) {
        if (bound(count) != 1) {
            msg_err("bound variable value mismatch\n");
            exit(EXIT_FAILURE);
        }
        terminate_reached = true;
        return;
    }
    if (closure_self() != self) {
        msg_err("self mismatch: %p, %p, terminate %d\n", closure_self(), self, terminate);
        exit(EXIT_FAILURE);
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
        msg_err("return value mismatch\n");
        return EXIT_FAILURE;
    }
    if (heap_allocated(h) > heap_occupancy) {
        msg_err("leak after closure_finish(): prev %ld, now %ld\n",
                heap_occupancy, heap_allocated(h));
        return EXIT_FAILURE;
    }
    heap_occupancy = heap_allocated(h);
    test1_type t = closure(h, test1, 0);
    apply(t, t, false);
    deallocate_closure(t);
    if (heap_allocated(h) > heap_occupancy) {
        msg_err("leak after deallocate_closure(): prev %ld, now %ld\n",
                heap_occupancy, heap_allocated(h));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
