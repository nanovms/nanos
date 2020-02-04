extern void init_symbols(heap h, heap init);
typedef struct symbol *symbol;
symbol intern(buffer);
symbol intern_u64(u64);

string symbol_string(symbol s);

#define sym(name)\
    ({static symbol __s = 0;\
      if (!__s){char x[] = #name; __s = intern(alloca_wrap_buffer(x, sizeof(x)-1));} \
     __s;})              

#define sym_this(name)\
    (intern(alloca_wrap_buffer(name, runtime_strlen(name))))

table symbol_table();
key key_from_symbol(void *z);
