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
