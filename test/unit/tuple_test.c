#include <runtime.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define COUNT_ELM   10

#define test_assert(expr) do { \
if (expr) ; else { \
    msg_err("%s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
    goto fail; \
} \
} while (0)

boolean all_tests(heap h)
{
    boolean failure = true;

    char *tst[COUNT_ELM] = {"00","10","20","30","40","50","60","70","80","90"};

    // check count
    tuple t1 = allocate_tuple();
    for(u8 i = 0; i < COUNT_ELM; i++){
        buffer b1 = wrap_buffer_cstring(h, tst[i]);
        table_set(t1, intern_u64(i), b1);
    }
    test_assert(table_elements(t1) == COUNT_ELM);//rprintf("%t\n", t1);

    // from vector
    vector v1 = allocate_vector(h, COUNT_ELM);
    for(u8 i = 0; i < COUNT_ELM; i++){
        vector_push(v1, wrap_buffer_cstring(h, tst[i]));
    }
    tuple t2 = tuple_from_vector(v1);
    test_assert(table_elements(t2) == COUNT_ELM);//rprintf("%t\n", t2);
    destruct_tuple(t2, true);
    deallocate_vector(v1);

    // value <-> U64
    u64 u1 = 777;
    value val = value_from_u64(h, u1);
    u64 u2;
    test_assert(u64_from_value(val, &u2));
    test_assert(u1 == u2);//rprintf("u1=%d,u2=%d\n",u1, u2);

    // tuple find
    for (u64 j1 = 0; j1 < COUNT_ELM; j1++){
        value v2 = table_find(t1, intern_u64(j1));
        u64 j2;
        test_assert(u64_from_value(v2, &j2));
        u64 j3 = j1 * 10;
        test_assert(j3 == j2);//rprintf("j3=%d,j2=%d\n",j3, j2);
    }

    failure = false;
fail:
    destruct_tuple(t1, true);
    return failure;
}

boolean encode_decode_test(heap h)
{
    boolean failure = true;

    // encode
    buffer b3 = allocate_buffer(h, 128);
    tuple t3 = allocate_tuple();
    table_set(t3, intern_u64(1), wrap_buffer_cstring(h, "200"));

    tuple tdict1 = allocate_tuple();
    u64 total_entries = 0;

    encode_tuple(b3, tdict1, t3, &total_entries);

    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1);

    // decode
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    total_entries = 0;
    u64 obsolete_entries = 0;
    tuple t4 = decode_value(h, tdict2, b3, &total_entries, &obsolete_entries);

    test_assert((total_entries == 1) && (obsolete_entries == 0));
    buffer buf = allocate_buffer(h, 128);
    bprintf(buf, "%t", t4);
    test_assert(strncmp(buf->contents, "(1:200)", buffer_length(buf)) == 0);

    // update tuple by removing an entry
    obsolete_entries = 0;
    encode_eav(b3, tdict1, t3, intern_u64(1), 0, &obsolete_entries);
    test_assert(obsolete_entries == 2);
    obsolete_entries = 0;
    test_assert(decode_value(h, tdict2, b3,
        &total_entries, &obsolete_entries) == t4);
    test_assert(!table_find(t4, intern_u64(1)));
    test_assert((total_entries == 2) && (obsolete_entries == 2));

    destruct_tuple(t4, true);
    failure = false;
fail:
    destruct_tuple(t3, true);
    return failure;
}

boolean encode_decode_reference_test(heap h)
{
    boolean failure = true;

    // encode
    buffer b3 = allocate_buffer(h, 128);
    tuple t3 = allocate_tuple();
    tuple t33 = allocate_tuple();
    table_set(t33, intern_u64(1), wrap_buffer_cstring(h, "200"));
    table_set(t3, intern_u64(1), t33);
    table_set(t3, intern_u64(2), t33);

    tuple tdict1 = allocate_tuple();
    u64 total_entries = 0;

    encode_tuple(b3, tdict1, t3, &total_entries);

    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 4);    /* 2 entries for t3, plus 2 for t33 */

    // decode
    total_entries = 0;
    u64 obsolete_entries = 0;
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    tuple t4 = decode_value(h, tdict2, b3, &total_entries, &obsolete_entries);

    /* t33 has been encoded twice (because it is associated to 2 different
     * symbols in t3), and the second encoding obsoletes the first encoding. */
    test_assert((total_entries == 4) && (obsolete_entries == 1));

    buffer buf = allocate_buffer(h, 128);
    bprintf(buf, "%t", t4);
    test_assert((strncmp(buf->contents, "(1:(1:200) 2:(1:200))", buf->length) == 0) ||
                (strncmp(buf->contents, "(2:(1:200) 1:(1:200))", buf->length) == 0));
    failure = false;
fail:
    return failure;
}

boolean encode_decode_lengthy_test(heap h)
{
    boolean failure = true;

    // encode
    buffer b3 = allocate_buffer(h, 1000*50);
    tuple t3 = allocate_tuple();
    for (int i=0; i<1000; ++i)
    {
        table_set(t3, intern_u64(i), wrap_buffer_cstring(h, "100"));
    }

    tuple tdict1 = allocate_tuple();
    u64 total_entries = 0;

    encode_tuple(b3, tdict1, t3, &total_entries);

    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1000);

    // decode
    total_entries = 0;
    u64 obsolete_entries = 0;
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    tuple t4 = decode_value(h, tdict2, b3, &total_entries, &obsolete_entries);

    test_assert((total_entries == 1000) && (obsolete_entries == 0));
    test_assert(t4->count == 1000);

    destruct_tuple(t4, true);
    failure = false;
fail:
    destruct_tuple(t3, true);
    return failure;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    int failure = 0;

    failure |= all_tests(h);
    failure |= encode_decode_test(h);
    failure |= encode_decode_reference_test(h);
    failure |= encode_decode_lengthy_test(h);

    if (failure) {
        msg_err("Test failed\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
