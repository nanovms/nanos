extern void init_symbols(heap h);
typedef struct symbol *symbol;
symbol intern(buffer);

string symbol_string(symbol s);

#define sym(name)\
    ({static symbol __s = 0;\
      if (!__s){char x[] = #name; __s = intern(alloca_wrap_buffer(x, sizeof(x)-1));} \
     __s;})              

table symbol_table();
typedef table tuple;
tuple allocate_tuple();
key key_from_symbol(void *z);
boolean symbol_equal(void *a, void* b);

static inline vector tuple_vector(heap h, tuple t)
{
    void *x;
    vector v = allocate_vector(h, table_elements(t));
    buffer num = little_stack_buffer(50);

    for (int i = 0; buffer_clear(num), format_number(num, i, 10, 1), x = table_find(t, intern(num)); i++)
        vector_push(v, x);

    return v;
}
