extern void init_symbols();

symbol intern(string);

extern key symbol_key(heap, symbol);

string symbol_string(symbol s);

// xxx - t0 only
#define sym(name)\
    ({static symbol __s = 0;\
     if (!__s) __s = intern(aprintf(transient, "%s", #name));\
     __s;\
     })              
