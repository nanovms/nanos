#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif

BSS_RO_AFTER_INIT static table symbols;
BSS_RO_AFTER_INIT static heap sheap;
BSS_RO_AFTER_INIT static heap iheap;

#ifdef KERNEL

static struct spinlock slock;

#define sym_lock_init() spin_lock_init(&slock)
#define sym_lock()      spin_lock(&slock)
#define sym_unlock()    spin_unlock(&slock)

#else

#define sym_lock_init()
#define sym_lock()
#define sym_unlock()

#endif

struct symbol {
    string s;
    key k;
};

symbol intern_u64(u64 u)
{
    buffer b = little_stack_buffer(20);
    print_number(b, u, 10, 0, false);
    return intern(b);
}

static u64 s[2] = { 0xa5a5beefa5a5cafe, 0xbeef55aaface55aa };

#ifndef ROL
#define ROL(x, y) (((x) << y) | (x) >> (64 - (y)))
#endif

static u64 intern_hash_u64()
{
    u64 s0 = s[0];
    u64 s1 = s[1];
    u64 result = s0 + s1;

    s1 ^= s0;
    s[0] = ROL(s0, 55) ^ s1 ^ (s1 << 14); // a, b
    s[1] = ROL(s1, 36); // c
    return result;
}

symbol intern(string name)
{
    symbol s;
    sym_lock();
    if (!(s = table_find(symbols, name))) {
        // shouldnt really be on transient
        buffer b = allocate_buffer(iheap, buffer_length(name));
        if (b == INVALID_ADDRESS)
            goto alloc_fail;
        assert(push_buffer(b, name));
        s = allocate(sheap, sizeof(struct symbol));
        if (s == INVALID_ADDRESS)
            goto alloc_fail;
        s->k = intern_hash_u64();
        s->s = b;
        table_set(symbols, b, s);
    }
    sym_unlock();
    return s;
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
    sym_lock_init();
}

