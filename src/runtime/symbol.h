extern void init_symbols(heap h, heap init);
typedef struct symbol *symbol;
symbol intern(buffer);
symbol intern_u64(u64);

string symbol_string(symbol s);

#define sym(name)           \
    ({static symbol __s = 0;\
      if (!__s){char x[] = #name; __s = intern(alloca_wrap_buffer(x, sizeof(x)-1));} \
     __s;})              

#define sym_this(name)  ({                              \
    assert_string_literal(name);                        \
    intern(alloca_wrap_buffer(name, sizeof(name) - 1)); \
})

#define sym_sstring(name)   ({                      \
    sstring __n = name;                             \
    intern(alloca_wrap_buffer(__n.ptr, __n.len));   \
})

table symbol_table();
key key_from_symbol(void *z);
