extern void init_symbols();
typedef buffer symbol;
symbol intern(buffer);

extern key symbol_key(heap, symbol);

string symbol_string(symbol s);

#define sym(name)\
    ({static symbol __s = 0;\
      if (!__s){char x[] = #name; __s = intern(alloca_wrap_buffer(x, sizeof(x)-1));} \
     __s;})              
