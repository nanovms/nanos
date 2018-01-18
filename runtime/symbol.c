#include <runtime.h>

static table symbols;
static heap sheap;
typedef buffer symbol;

struct symbol {
    key k;
    string s;
};

static key key_from_symbol(symbol s)
{
    return(s->k);
}

symbol intern(string name)
{
    symbol s;

    if (!(s= get(symbols, name))){
        s=allocate(sheap, t_symbol);
        s->k = *genrand_u32(sheap);
        s->s = copy(sheap, name);
        set(symbols, s->s, s); 
    }
    return(s);
}

static void traverse_symbol(symbol s, void (*f)())
{
    (*f)(&s->s);
}


string symbol_string(symbol s)
{
    return(s->s);
}

void init_symbols()
{
    sheap = allocate_leaky_heap(pages);
    symbols = allocate_table(sheap);
}

