#include <runtime.h>
#include <stdlib.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define TABLETEST_ELEM_COUNT	512

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

static boolean basic_table_tests(heap h, u64 (*key_function)(void *x))
{
    table t = allocate_table(h, key_function, pointer_equal);
    u64 count;

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
    for (count = 0; count < TABLETEST_ELEM_COUNT; count++) {
        table_set(t, (void *)count, (void *)(count + 1));
    }

    /* This should not add anything to the table. */
    table_set(t, (void *)count, 0);

    count = 0;
    table_foreach(t, n, v) {
        if ((u64)v != (u64)n + 1) {
            msg_err("table_foreach() invalid value %d for name %d, "
                    "should be %d\n", (u64)v, (u64)n, (u64)n + 1);
            return false;
        }
        count++;
    }
    if (count != TABLETEST_ELEM_COUNT) {
        msg_err("table_foreach() invalid iteration count %d\n", count);
        return false;
    }
    for (count = 0; count < TABLETEST_ELEM_COUNT; count++) {
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
    count = table_elements(t);
    if (count != TABLETEST_ELEM_COUNT - 1) {
        msg_err("invalid table_elements() %d, should be %d\n", count,
                TABLETEST_ELEM_COUNT - 1);
        return false;
    }

    return true;
}

static boolean one_elem_table_tests(heap h)
{
    table t = allocate_table(h, silly_key, anything_equals);
    u64 count;

    for (count = 0; count < TABLETEST_ELEM_COUNT; count++) {
        table_set(t, (void *)count, (void *)(count + 1));
    }
    count = 0;
    table_foreach(t, n, v) {
        if (n != 0) {
            msg_err("table_foreach() invalid name %d\n", (u64)n);
            return false;
        }
        if ((u64)v != TABLETEST_ELEM_COUNT) {
            msg_err("table_foreach() invalid value %d for name %d, "
                    "should be %d\n", (u64)v, (u64)n, TABLETEST_ELEM_COUNT);
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
    for (count = 0; count < TABLETEST_ELEM_COUNT; count++) {
        u64 v = (u64)table_find(t, (void *)count);

        if (!v) {
            msg_err("element %d not found\n", count);
            return false;
        }
        if (v != TABLETEST_ELEM_COUNT) {
            msg_err("element %d invalid value %d, should be %d\n", count, v,
                    TABLETEST_ELEM_COUNT);
            return false;
        }
    }
    if (!table_find(t, (void *)count)) {
        msg_err("element %d not found\n", count);
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_table_tests(h, identity_key)) {
        msg_err("Identity key table test failed\n");
        goto fail;
    }
    if (!basic_table_tests(h, silly_key)) {
        msg_err("Silly key table test failed\n");
        goto fail;
    }
    if (!basic_table_tests(h, less_silly_key)) {
        msg_err("Less silly key table test failed\n");
        goto fail;
    }
    if (!one_elem_table_tests(h)) {
        msg_err("One-element table test failed\n");
        goto fail;
    }
    exit(EXIT_SUCCESS);
fail:
	exit(EXIT_FAILURE);
}
