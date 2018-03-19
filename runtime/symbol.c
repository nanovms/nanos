#include <runtime.h>

static table symbols;
static heap sheap;

// move prng out
static u64 s[2];

#define rol(__x, __b)\
     ({\
        __asm__("rol %1, %0": "=g"(__x): "i" (__b));\
        __x;\
     })\

u64 rng_next(void) {
    u64 s0 = s[0];
    u64 s1 = s[1];
    u64 result = s0 + s1;

    s1 ^= s0;
    s[0] = rol(s0, 55) ^ s1 ^ (s1 << 14); // a, b
    s[1] = rol(s1, 36); // c

    return result;
}

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
        s->k = rng_next();
        s->s = b;
        table_set(symbols, s->s, s); 
    }
    return(s);
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


// region?
tuple allocate_tuple()
{
    return allocate_table(sheap, key_from_symbol, pointer_equal);
}


void init_symbols(heap h)
{
    sheap = h;
    symbols = allocate_table(h, fnv64, buffer_compare);
}

