#include <runtime.h>
#include <stdlib.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define COUNT_ELM   10

#define test_assert(expr) do { \
if (expr) ; else { \
    msg_err("%s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
    fail = 1; \
} \
} while (0)

int main(int argc, char **argv)
{
    boolean fail = false;
    heap h = init_process_runtime();
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
    deallocate_vector(v1);

    // value <-> U64
    u64 u1 = 777;
    value val = value_from_u64(h, u1);
    u64 u2 = u64_from_value(val);
    test_assert(u1 == u2);//rprintf("u1=%d,u2=%d\n",u1, u2);

    // tuple find
    for (u64 j1 = 0; j1 < COUNT_ELM; j1++){
        value v2 = table_find(t1, intern_u64(j1));
        u64 j2 = u64_from_value(v2);
        u64 j3 = j1 * 10;
        test_assert(j3 == j2);//rprintf("j3=%d,j2=%d\n",j3, j2);
    }

    // encode
    buffer b3 = allocate_buffer(h, 128);
    tuple t3 = allocate_tuple();
    table_set(t3, intern_u64(1), wrap_buffer_cstring(h, "200"));//rprintf("tuple to enc: %t\n", t3);

    tuple tdict1 = allocate_tuple();
    table_set(tdict1, intern_u64(1), wrap_buffer_cstring(h, "100"));//rprintf("dict tuple: %t\n", tdict1);

    encode_tuple(b3, tdict1, t3);

    test_assert(buffer_length(b3) > 0);//rprintf("buffer b3 = : %X", b3);

    // decode
    table tdict2 = allocate_table(h, identity_key, pointer_equal);
    //table_set(tdict2, intern_u64(1), wrap_buffer_cstring(h, "200"));
    //tuple t4 = decode_value(h, tdict2, b3);//rprintf("%t\n", t4);
    decode_value(h, tdict2, b3);


    if (fail){
        msg_err("tuple test failed\n");
        exit(EXIT_FAILURE);
    }
    rprintf("tuple test success\n");
    exit(EXIT_SUCCESS);
}
