#include <runtime.h>
#include <stdlib.h>

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

    table_validate(t, "basic_table_tests: alloc");

    if (table_elements(t) != 0) {
        msg_err("table_elements() not zero on empty table\n");
        return false;
    }

    table_foreach(t, n, v) {
        (void) n;
        (void) v;
        msg_err("table_foreach() on empty table\n");
        return false;
    }

    for (count = 0; count < n_elem; count++) {
        table_set(t, (void *)count, (void *)(count + 1));
    }

    table_validate(t, "basic_table_tests: after fill");

    /* This should not add anything to the table. */
    table_set(t, (void *)count, 0);

    table_validate(t, "basic_table_tests: after null set");

    count = 0;
    table_foreach(t, n, v) {
        if ((u64)v != (u64)n + 1) {
            msg_err("table_foreach() invalid value %d for name %d, "
                    "should be %d\n", (u64)v, (u64)n, (u64)n + 1);
            return false;
        }
        count++;
    }

    if (count != n_elem) {
        msg_err("table_foreach() invalid iteration count %d\n", count);
        return false;
    }

    for (count = 0; count < n_elem; count++) {
        u64 v = (u64)table_find(t, (void *)count);

        if (!v) {
            msg_err("element %d not found\n", count);
            return false;
        }
        if (v != count + 1) {
            msg_err("element %d invalid value %d, should be %d\n", count, v,
                    count + 1);
            return false;
        }
    }

    if (table_find(t, (void *)count)) {
        msg_err("found unexpected element %d\n", count);
        return false;
    }

    /* Remove one element from the table. */
    table_set(t, 0, 0);
    if (table_find(t, 0)) {
        msg_err("found unexpected element 0\n");
        return false;
    }

    table_validate(t, "basic_table_tests: after remove one");

    count = table_elements(t);
    if (count != n_elem - 1) {
        msg_err("invalid table_elements() %d, should be %d\n", count,
                n_elem - 1);
        return false;
    }

    /* Remove the rest: first forward (skimming off top of each bucket) */
    for (count = 1; count < (n_elem / 2); count++)
        table_set(t, (void *)count, 0);

    table_validate(t, "basic_table_tests: after remove forward");

    /* ... and then backward (descend to bottom of each bucket) */
    for (count = n_elem - 1; count >= (n_elem / 2); count--)
        table_set(t, (void *)count, 0);

    table_validate(t, "basic_table_tests: after remove backward");

    count = table_elements(t);
    if (count != 0) {
        msg_err("invalid table_elements() %d, should be 0\n");
        return false;
    }

    deallocate_table(t);
    if (heap_allocated(h) != heap_occupancy) {
        msg_err("leak: heap_allocated(h) %ld, originally %ld\n", heap_allocated(h), heap_occupancy);
        return false;
    }
    return true;
}

static boolean one_elem_table_tests(heap h, u64 n_elem)
{
    u64 heap_occupancy = heap_allocated(h);
    table t = allocate_table(h, silly_key, anything_equals);
    u64 count;

    table_validate(t, "one_elem_table_tests: after alloc");

    for (count = 0; count < n_elem; count++) {
        table_set(t, (void *)count, (void *)(count + 1));
    }

    table_validate(t, "one_elem_table_tests: after fill");

    count = 0;
    table_foreach(t, n, v) {
        if (n != 0) {
            msg_err("table_foreach() invalid name %d\n", (u64)n);
            return false;
        }
        if ((u64)v != n_elem) {
            msg_err("table_foreach() invalid value %d for name %d, "
                    "should be %d\n", (u64)v, (u64)n, n_elem);
            return false;
        }
        count++;
    }

    if (count != 1) {
        msg_err("table_foreach() invalid iteration count %d\n", count);
        return false;
    }

    count = table_elements(t);
    if (count != 1) {
        msg_err("invalid table_elements() %d, should be 1\n", count);
        return false;
    }

    for (count = 0; count < n_elem; count++) {
        u64 v = (u64)table_find(t, (void *)count);

        if (!v) {
            msg_err("element %d not found\n", count);
            return false;
        }
        if (v != n_elem) {
            msg_err("element %d invalid value %d, should be %d\n", count, v,
                    n_elem);
            return false;
        }
    }

    if (!table_find(t, (void *)count)) {
        msg_err("element %d not found\n", count);
        return false;
    }

    table_clear(t);
    if (table_find(t, (void *)count)) {
        msg_err("element found after table_clear()\n");
        return false;
    }
    count = table_elements(t);
    if (count != 0) {
        msg_err("invalid table_elements() %d after table_clear()\n", count);
        return false;
    }

    deallocate_table(t);
    if (heap_allocated(h) != heap_occupancy) {
        msg_err("leak: heap_allocated(h) %ld, originally %ld\n", heap_allocated(h), heap_occupancy);
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
        msg_err("Identity key table test failed\n");
        goto fail;
    }

    if (!basic_table_tests(h, silly_key, BASIC_ELEM_COUNT)) {
        msg_err("Silly key table test failed\n");
        goto fail;
    }

    if (!basic_table_tests(h, less_silly_key, BASIC_ELEM_COUNT)) {
        msg_err("Less silly key table test failed\n");
        goto fail;
    }

    if (!one_elem_table_tests(h, BASIC_ELEM_COUNT)) {
        msg_err("One-element table test failed\n");
        goto fail;
    }

    if (!basic_table_tests(h, identity_key, STRESS_ELEM_COUNT)) {
        msg_err("Stress table test failed\n");
        goto fail;
    }
    exit(EXIT_SUCCESS);
fail:
    exit(EXIT_FAILURE);
}
