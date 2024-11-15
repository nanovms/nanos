#include <runtime.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define COUNT_ELM   10

#define test_assert(expr) do { \
if (expr) ; else { \
    msg_err("%s: %s -- failed at %s:%d", func_ss, ss(#expr), file_ss, __LINE__); \
    goto fail; \
} \
} while (0)

boolean all_tests(heap h)
{
    boolean failure = true;

    sstring tst[COUNT_ELM] = {
        ss_static_init("00"),
        ss_static_init("10"),
        ss_static_init("20"),
        ss_static_init("30"),
        ss_static_init("40"),
        ss_static_init("50"),
        ss_static_init("60"),
        ss_static_init("70"),
        ss_static_init("80"),
        ss_static_init("90"),
    };

    // check count
    tuple t1 = allocate_tuple();
    for(u8 i = 0; i < COUNT_ELM; i++){
        buffer b1 = wrap_string_sstring(tst[i]);
        set(t1, value_from_u64(i), b1);
    }
    test_assert(tuple_count(t1) == COUNT_ELM);//rprintf("%v\n", t1);

    // from vector
    vector v1 = allocate_vector(h, COUNT_ELM);
    for(u8 i = 0; i < COUNT_ELM; i++){
        vector_push(v1, wrap_string_sstring(tst[i]));
    }
    test_assert(vector_length(v1) == COUNT_ELM);//rprintf("%v\n", t2);
    deallocate_vector(v1);

    // value <-> u64
    u64 u1 = 777;
    value val = value_from_u64(u1);//rprintf("u1 val %v\n", val);
    u64 u2;
    test_assert(u64_from_value(val, &u2));
    test_assert(u1 == u2);//rprintf("u1=%d,u2=%d\n",u1, u2);

    // value <-> s64
    s64 s1 = -777;
    val = value_from_s64(s1);//rprintf("s1 val %v\n", val);
    s64 s2;
    test_assert(s64_from_value(val, &s2));
    test_assert(s1 == s2);//rprintf("s1=%d,s2=%d\n",s1, s2);

    // value rewrites
    val = value_from_u64(u1);
    u1 = 888;
    val = value_rewrite_u64(val, u1);
    test_assert(u64_from_value(val, &u2));
    test_assert(u1 == u2);

    val = value_from_s64(s1);
    s1 = -888;
    val = value_rewrite_s64(val, s1);
    test_assert(s64_from_value(val, &s2));
    test_assert(s1 == s2);

    // test range limits
    u1 = -1ull;
    val = value_from_u64(u1);//rprintf("u1 val %v\n", val);
    test_assert(!is_immediate_integer(val));
    test_assert(u64_from_value(val, &u2));
    test_assert(u1 == u2);//rprintf("u1=%d,u2=%d\n",u1, u2);

    u1 = IMM_UINT_MAX;
    val = value_from_u64(u1);//rprintf("u1 val %v\n", val);
    test_assert(is_immediate_integer(val));
    test_assert(u64_from_value(val, &u2));
    test_assert(u1 == u2);//rprintf("u1=%d,u2=%d\n",u1, u2);

    u1 = U64_MAX;
    val = value_from_u64(u1);//rprintf("u1 val %v\n", val);
    test_assert(!is_immediate_integer(val));
    test_assert(u64_from_value(val, &u2));
    test_assert(u1 == u2);//rprintf("u1=%d,u2=%d\n",u1, u2);

    s1 = S64_MIN;
    val = value_from_s64(s1);//rprintf("s1 val %v\n", val);
    test_assert(!is_immediate_integer(val));
    test_assert(s64_from_value(val, &s2));
    test_assert(s1 == s2);//rprintf("s1=%d,s2=%d\n",s1, s2);

    s1 = IMM_SINT_MIN;
    val = value_from_s64(s1);//rprintf("s1 val %v\n", val);
    test_assert(is_immediate_integer(val));
    test_assert(s64_from_value(val, &s2));
    test_assert(s1 == s2);//rprintf("s1=%d,s2=%d\n",s1, s2);

    // tuple find
    for (u64 j1 = 0; j1 < COUNT_ELM; j1++){
        value v2 = get(t1, value_from_u64(j1)); // XXX get string or int
        u64 j2;
        test_assert(u64_from_value(v2, &j2));
        u64 j3 = j1 * 10;
        test_assert(j3 == j2);//rprintf("j3=%d,j2=%d\n",j3, j2);
    }

    // get symbol associated to a value
    symbol sym1 = sym(tuple_test1), sym2 = sym(tuple_test2);
    test_assert(tuple_get_symbol(t1, val) == 0);
    set(t1, sym1, val);
    test_assert(tuple_get_symbol(t1, val) == sym1);
    set(t1, sym2, val);
    test_assert((tuple_get_symbol(t1, val) == sym1) || (tuple_get_symbol(t1, val) == sym2));
    set(t1, sym1, 0);
    set(t1, sym2, 0);

    // tuple clone
    v1 = allocate_vector(h, 1);
    set(t1, sym(v1), v1);
    tuple t2 = allocate_tuple();
    set(t2, sym(b0), wrap_string_sstring(tst[0]));
    set(t2, sym(b1), wrap_string_sstring(tst[1]));
    set(t1, sym(t2), t2);
    tuple t3 = clone_tuple(t1);
    vector v2 = get(t3, sym(v1));
    test_assert((v2 != v1) && (vector_length(v2) == vector_length(v1)));
    val = get(t3, intern_u64(1));
    test_assert(u64_from_value(val, &u1) && (u1 == 10));
    tuple t4 = get(t3, sym(t2));
    test_assert((t4 != t2) && (tuple_count(t4) == tuple_count(t2)));
    destruct_value(t3, true);

    failure = false;
fail:
    destruct_value(t1, true);
    return failure;
}

boolean encode_decode_test(heap h)
{
    boolean failure = true;

    // encode
    buffer b3 = allocate_buffer(h, 128);
    tuple t3 = allocate_tuple();
    set(t3, value_from_u64(1), value_from_u64(200));

    table tdict1 = allocate_table(h, identity_key, pointer_equal);
    u64 total_entries = 0;

    encode_tuple(b3, tdict1, t3, &total_entries);

    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1);

    // decode
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    total_entries = 0;
    u64 obsolete_entries = 0;
    tuple t4 = decode_value(h, tdict2, b3, &total_entries, &obsolete_entries, false);

    test_assert((total_entries == 1) && (obsolete_entries == 0));
    buffer buf = allocate_buffer(h, 128);
    bprintf(buf, "%v", t4);
    test_assert(strncmp(buf->contents, "(1:200)", buffer_length(buf)) == 0);

    // update tuple by removing an entry
    obsolete_entries = 0;
    encode_eav(b3, tdict1, t3, intern_u64(1), 0, &obsolete_entries);
    test_assert(obsolete_entries == 2);
    obsolete_entries = 0;
    test_assert(decode_value(h, tdict2, b3,
                             &total_entries, &obsolete_entries, false) == t4);
    test_assert(!get(t4, intern_u64(1)));
    test_assert((total_entries == 2) && (obsolete_entries == 2));

    // test signed ints
    set(t3, integer_key(1), value_from_s64(-3));
    total_entries = 0;
    table_clear(tdict1);
    encode_tuple(b3, tdict1, t3, &total_entries);
    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1);

    // decode
    total_entries = 0;
    obsolete_entries = 0;
    table_clear(tdict1);
    t4 = decode_value(h, tdict1, b3, &total_entries, &obsolete_entries, false);

    test_assert((total_entries == 1) && (obsolete_entries == 0));
    buffer_clear(buf);
    bprintf(buf, "%v", t4);
    test_assert(strncmp(buf->contents, "(1:-3)", buffer_length(buf)) == 0);

    destruct_value(t4, true);

    // test min signed
    set(t3, integer_key(1), value_from_s64(S64_MIN));
    total_entries = 0;
    table_clear(tdict1);
    encode_tuple(b3, tdict1, t3, &total_entries);
    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1);

    // decode
    total_entries = 0;
    obsolete_entries = 0;
    table_clear(tdict1);
    t4 = decode_value(h, tdict1, b3, &total_entries, &obsolete_entries, false);

    test_assert((total_entries == 1) && (obsolete_entries == 0));
    buffer_clear(buf);
    bprintf(buf, "%v", t4);
    test_assert(strncmp(buf->contents, "(1:-9223372036854775808)", buffer_length(buf)) == 0);

    // test max unsigned
    set(t3, integer_key(1), value_from_u64(U64_MAX));
    total_entries = 0;
    table_clear(tdict1);
    encode_tuple(b3, tdict1, t3, &total_entries);
    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1);

    // decode
    total_entries = 0;
    obsolete_entries = 0;
    table_clear(tdict1);
    t4 = decode_value(h, tdict1, b3, &total_entries, &obsolete_entries, false);

    test_assert((total_entries == 1) && (obsolete_entries == 0));
    buffer_clear(buf);
    bprintf(buf, "%v", t4);
    test_assert(strncmp(buf->contents, "(1:18446744073709551615)", buffer_length(buf)) == 0);

    destruct_value(t4, true);
    failure = false;
fail:
    destruct_value(t3, true);
    return failure;
}

boolean encode_decode_reference_test(heap h)
{
    boolean failure = true;

    // encode
    buffer b3 = allocate_buffer(h, 128);
    tuple t3 = allocate_tuple();
    tuple t33 = allocate_tuple();
    set(t33, value_from_u64(1), wrap_string_cstring("200"));
    set(t3, value_from_u64(1), t33);
    set(t3, value_from_u64(2), t33);

    table tdict1 = allocate_table(h, identity_key, pointer_equal);
    u64 total_entries = 0;

    encode_tuple(b3, tdict1, t3, &total_entries);

    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 3);    /* 2 entries for t3, plus 1 for t33 (despite two refs) */

    // decode
    total_entries = 0;
    u64 obsolete_entries = 0;
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    tuple t4 = decode_value(h, tdict2, b3, &total_entries, &obsolete_entries, false);

    /* t33 has been encoded once (despite being associated to 2 different symbols in t3) */
    test_assert((total_entries == 3) && (obsolete_entries == 0));

    buffer buf = allocate_buffer(h, 128);
    bprintf(buf, "%v", t4);
    test_assert((strncmp(buf->contents, "(1:(1:200) 2:<visited>)", buffer_length(buf)) == 0) ||
                (strncmp(buf->contents, "(2:(1:200) 1:<visited>)", buffer_length(buf)) == 0));
    failure = false;
fail:
    return failure;
}

boolean encode_decode_self_reference_test(heap h)

{
    boolean failure = true;

    // encode
    buffer b3 = allocate_buffer(h, 128);
    tuple t3 = allocate_tuple();
    set(t3, intern_u64(1), t3);

    table tdict1 = allocate_table(h, identity_key, pointer_equal);
    u64 total_entries = 0;

    encode_tuple(b3, tdict1, t3, &total_entries);

    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1);

    // decode
    total_entries = 0;
    u64 obsolete_entries = 0;
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    tuple t4 = decode_value(h, tdict2, b3, &total_entries, &obsolete_entries, false);

    test_assert((total_entries == 1) && (obsolete_entries == 0));

    buffer buf = allocate_buffer(h, 128);
    bprintf(buf, "%v", t4);
    test_assert((strncmp(buf->contents, "(1:<visited>)", buffer_length(buf)) == 0));
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
        set(t3, value_from_u64(i), wrap_string_cstring("100"));
    }

    table tdict1 = allocate_table(h, identity_key, pointer_equal);
    u64 total_entries = 0;

    encode_tuple(b3, tdict1, t3, &total_entries);

    test_assert(buffer_length(b3) > 0);
    test_assert(total_entries == 1000);

    // decode
    total_entries = 0;
    u64 obsolete_entries = 0;
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    tuple t4 = decode_value(h, tdict2, b3, &total_entries, &obsolete_entries, false);

    test_assert((total_entries == 1000) && (obsolete_entries == 0));
    test_assert(tuple_count(t4) == 1000);

    destruct_value(t4, true);
    failure = false;
fail:
    destruct_value(t3, true);
    return failure;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    int failure = 0;

    failure |= all_tests(h);
    failure |= encode_decode_test(h);
    failure |= encode_decode_reference_test(h);
    failure |= encode_decode_self_reference_test(h);
    failure |= encode_decode_lengthy_test(h);

    if (failure) {
        msg_err("Tuple test failed");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
