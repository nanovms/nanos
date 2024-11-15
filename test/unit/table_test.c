#include <runtime.h>

#include "../test_utils.h"

static inline key silly_key(void *a)
{
    return 0;
}

static inline key less_silly_key(void *a)
{
    return ((u64)a & 0x8);
}

static inline boolean anything_equals(void *a, void* b)
{
    return true;
}

static boolean basic_table_tests(heap h, u64 (*key_function)(void *x), u64 n_elem)
{
    u64 heap_occupancy = heap_allocated(h);
    table t = allocate_table(h, key_function, pointer_equal);
    u64 count;
    u64 val;

    table_validate(t, ss("basic_table_tests: alloc"));

    if (table_elements(t) != 0) {
        msg_err("%s error: table_elements() not zero on empty table", func_ss);
        return false;
    }

    table_foreach(t, n, v) {
        (void) n;
        (void) v;
        msg_err("%s error: table_foreach() on empty table", func_ss);
        return false;
    }

    for (count = 0; count < n_elem; count++) {
        table_set(t, (void *)count, (void *)(count + 1));
    }

    table_validate(t, ss("basic_table_tests: after fill"));

    /* This should not add anything to the table. */
    table_set(t, (void *)count, 0);

    table_validate(t, ss("basic_table_tests: after null set"));

    count = 0;
    table_foreach(t, n, v) {
        if ((u64)v != (u64)n + 1) {
            msg_err("%s error: table_foreach() invalid value %ld for name %ld, should be %ld",
                    func_ss, (u64)v, (u64)n, (u64)n + 1);
            return false;
        }
        count++;
    }

    if (count != n_elem) {
        msg_err("%s error: table_foreach() invalid iteration count %ld", func_ss, count);
        return false;
    }

    for (count = 0; count < n_elem; count++) {
        u64 v = (u64)table_find(t, (void *)count);

        if (!v) {
            msg_err("%s error: element %ld not found", func_ss, count);
            return false;
        }
        if (v != count + 1) {
            msg_err("%s error: element %ld invalid value %ld, should be %ld", func_ss, count, v,
                    count + 1);
            return false;
        }
    }

    if (table_find(t, (void *)count)) {
        msg_err("%s error: unexpected element %ld", func_ss, count);
        return false;
    }

    if (table_set_noreplace(t, pointer_from_u64(n_elem / 2), pointer_from_u64(1))) {
        msg_err("%s error: could replace element %ld", func_ss, n_elem / 2);
        return false;
    }

    /* Remove one element from the table. */
    table_set(t, 0, 0);
    if (table_find(t, 0)) {
        msg_err("%s error: unexpected element 0", func_ss);
        return false;
    }

    table_validate(t, ss("basic_table_tests: after remove one"));

    count = table_elements(t);
    if (count != n_elem - 1) {
        msg_err("%s error: invalid table_elements() %ld, should be %ld", func_ss, count,
                n_elem - 1);
        return false;
    }

    val = u64_from_pointer(table_remove(t, (pointer_from_u64(1))));
    if (val != 2) {
        msg_err("%s error: invalid element %ld removed, should be 2", func_ss, val);
        return false;
    }
    table_validate(t, ss("basic_table_tests: after table_remove()"));
    count = table_elements(t);
    if (count != n_elem - 2) {
        msg_err("%s error: invalid table_elements() %ld after table_remove(), should be %ld",
                func_ss, count, n_elem - 2);
        return false;
    }

    /* Remove the rest: first forward (skimming off top of each bucket) */
    for (count = 2; count < (n_elem / 2); count++)
        table_set(t, (void *)count, 0);

    table_validate(t, ss("basic_table_tests: after remove forward"));

    /* ... and then backward (descend to bottom of each bucket) */
    for (count = n_elem - 1; count >= (n_elem / 2); count--)
        table_set(t, (void *)count, 0);

    table_validate(t, ss("basic_table_tests: after remove backward"));

    count = table_elements(t);
    if (count != 0) {
        msg_err("%s error: invalid table_elements() %ld, should be 0", func_ss, count);
        return false;
    }

    if (!table_set_noreplace(t, pointer_from_u64(0), pointer_from_u64(n_elem))) {
        msg_err("%s failed to set element at 0", func_ss);
        return false;
    }
    val = u64_from_pointer(table_find(t, pointer_from_u64(0)));
    if (val != n_elem) {
        msg_err("%s error: unexpected element %ld at 0 after table_set_noreplace()",
                func_ss, val);
        return false;
    }

    deallocate_table(t);
    if (heap_allocated(h) != heap_occupancy) {
        msg_err("%s leak: heap_allocated(h) %ld, originally %ld",
                func_ss, heap_allocated(h), heap_occupancy);
        return false;
    }
    return true;
}

static boolean one_elem_table_tests(heap h, u64 n_elem)
{
    u64 heap_occupancy = heap_allocated(h);
    table t = allocate_table(h, silly_key, anything_equals);
    u64 count;

    table_validate(t, ss("one_elem_table_tests: after alloc"));

    for (count = 0; count < n_elem; count++) {
        table_set(t, (void *)count, (void *)(count + 1));
    }

    table_validate(t, ss("one_elem_table_tests: after fill"));

    count = 0;
    table_foreach(t, n, v) {
        if (n != 0) {
            msg_err("%s error: table_foreach() invalid name %ld", func_ss, (u64)n);
            return false;
        }
        if ((u64)v != n_elem) {
            msg_err("%s error: table_foreach() invalid value %ld for name %ld, should be %ld",
                    func_ss, (u64)v, (u64)n, n_elem);
            return false;
        }
        count++;
    }

    if (count != 1) {
        msg_err("%s error: table_foreach() invalid iteration count %ld", func_ss, count);
        return false;
    }

    count = table_elements(t);
    if (count != 1) {
        msg_err("%s error: invalid table_elements() %ld, should be 1", func_ss, count);
        return false;
    }

    for (count = 0; count < n_elem; count++) {
        u64 v = (u64)table_find(t, (void *)count);

        if (!v) {
            msg_err("%s error: element %ld not found", func_ss, count);
            return false;
        }
        if (v != n_elem) {
            msg_err("%s error: element %ld invalid value %ld, should be %ld", func_ss, count, v,
                    n_elem);
            return false;
        }
    }

    if (!table_find(t, (void *)count)) {
        msg_err("%s error: element %ld not found", func_ss, count);
        return false;
    }

    table_clear(t);
    if (table_find(t, (void *)count)) {
        msg_err("%s error: element found after table_clear()", func_ss);
        return false;
    }
    count = table_elements(t);
    if (count != 0) {
        msg_err("%s error: invalid table_elements() %ld after table_clear()", func_ss, count);
        return false;
    }

    deallocate_table(t);
    if (heap_allocated(h) != heap_occupancy) {
        msg_err("%s leak: heap_allocated(h) %ld, originally %ld",
                func_ss, heap_allocated(h), heap_occupancy);
        return false;
    }
    return true;
}

static boolean preallocated_table_tests(heap h, u64 (*key_function)(void *x), u64 n_elem)
{
    bytes mmapsize = pad(n_elem * sizeof (struct entry), PAGESIZE);

    /* make a parent heap for pages */
    heap m = allocate_mmapheap(h, mmapsize);


    u64 heap_occupancy_before = heap_allocated(h);
    heap pageheap = (heap)create_id_heap_backed(h, h, m, PAGESIZE, false);

    table t = allocate_table_preallocated(h, pageheap, key_function, pointer_equal, n_elem);
    u64 heap_occupancy = heap_allocated(h);
    u64 count;

    table_validate(t, ss("preallocated_table_tests: alloc"));

    if (table_elements(t) != 0) {
        msg_err("%s error: table_elements() not zero on empty table", func_ss);
        return false;
    }
    for (count = 0; count < n_elem; count++) {
        table_set(t, (void *)count, (void *)(count + 1));
    }

    table_validate(t, ss("preallocated_table_tests: after fill"));

    if (heap_allocated(h) != heap_occupancy) {
        msg_err("%s error: unexpected allocation: heap_allocated(h) %lu, originally %lu",
                func_ss, heap_allocated(h), heap_occupancy);
        return false;
    }

    table_set(t, 0, 0);
    if (table_find(t, 0)) {
        msg_err("%s error: unexpected element 0", func_ss);
        return false;
    }
    table_validate(t, ss("preallocated_table_tests: after remove one"));

    table_set(t, 0, (void *)1);
    table_validate(t, ss("preallocated_table_tests: after insert one"));


    deallocate_table(t);
    destroy_heap(pageheap);

    if (heap_allocated(h) != heap_occupancy_before) {
        msg_err("%s leak: heap_allocated(h) %lu, originally %lu",
                func_ss, heap_allocated(h), heap_occupancy_before);
        return false;
    }
    return true;
}

#define BASIC_ELEM_COUNT  512
#define STRESS_ELEM_COUNT (1ull << 20)

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_table_tests(h, identity_key, BASIC_ELEM_COUNT)) {
        test_error("identity key table test");
    }

    if (!basic_table_tests(h, silly_key, BASIC_ELEM_COUNT)) {
        test_error("silly key table test");
    }

    if (!basic_table_tests(h, less_silly_key, BASIC_ELEM_COUNT)) {
        test_error("less silly key table test");
    }

    if (!one_elem_table_tests(h, BASIC_ELEM_COUNT)) {
        test_error("one-element table test");
    }

    if (!basic_table_tests(h, identity_key, STRESS_ELEM_COUNT)) {
        test_error("stress table test");
    }

    if (!preallocated_table_tests(h, identity_key, BASIC_ELEM_COUNT)) {
        test_error("preallocated table test");
    }

    exit(EXIT_SUCCESS);
}
