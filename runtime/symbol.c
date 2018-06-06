#include <runtime.h>
static table symbols;
static heap sheap;

struct symbol {
    string s;
    key k;
};

symbol intern(string name)
{
    symbol s;

    if (!(s= table_find(symbols, name))){
        buffer b = allocate_buffer(sheap, buffer_length(name));
        push_buffer(b, name);
        s = allocate(sheap, sizeof(struct symbol));
        s->k = random_u64();
        s->s = b;
        table_set(symbols, s->s, s); 
    }
    return(tag(s, tag_symbol));
}

string symbol_string(symbol s)
{
    return(s->s);
}

// should make a heap that unmaps and returns pages to the heap on free
// and one that picks a new virtual address - this guy doesn't need
// and contiguity
// and dont forget my 2M aligned heap


key key_from_symbol(void *z)
{
    symbol s = z;
    return(s->k);
}


void init_symbols(heap h)
{
    sheap = h;
    symbols = allocate_table(h, fnv64, buffer_compare);
}

