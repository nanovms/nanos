#include <runtime.h>

static table symbols;
static heap sheap;
static heap iheap;

struct symbol {
    string s;
    key k;
};

symbol intern_u64(u64 u)
{
    buffer b = little_stack_buffer(20);
    print_number(b, u, 10, 0);
    return intern(b);
}

symbol intern(string name)
{
    symbol s;
    if (!(s = table_find(symbols, name))) {
        // shouldnt really be on transient
        buffer b = allocate_buffer(iheap, buffer_length(name));
        if (b == INVALID_ADDRESS)
            goto alloc_fail;
        push_buffer(b, name);
        s = allocate(sheap, sizeof(struct symbol));
        if (s == INVALID_ADDRESS)
            goto alloc_fail;
        symbol n = valueof(s);
        n->k = random_u64();
        n->s = b;
        table_set(symbols, b, s);
    }
    return valueof(s);
  alloc_fail:
    halt("intern: alloc fail\n");
}

string symbol_string(symbol s)
{
    return s->s;
}

key key_from_symbol(void *z)
{
    symbol s = z;
    return s->k;
}

void init_symbols(heap h, heap init)
{
    sheap = h;
    iheap = init;    
    symbols = allocate_table(iheap, fnv64, buffer_compare);
}

