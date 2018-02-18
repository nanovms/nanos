// patricia
// this can be radically compressed and aligned
// and dumped in a couple fixed pages
typedef struct entry {
    u64 base;   // 36.. 4k aligned
    u64 length; // 26...bits of 4k?
    node reference;  // could be bibop
    struct entry children[2]; // could be relative
    u8 position; // 6
}*entry

typedef struct vmap {
    heap h;
    entry *root;
} *vmap;

static inline u64 first_bit_set(u64 x)
{
    return __builtin_clzll(x);
}

// unmap

node resolve_vmap(vmap v, u64 address)
{
}

void insert_vmap(vmap v, u64 base, u64 length, node reference)
{
    entry n = allocate(v->h, sizeof(struct entry));
    n->base = base;
    n->length = length;
    n->reference = reference;
    int position = 64;
    entry e = v->root;

    if (!e) {
        v->root = e;
        return;
    }
    
    while(position > e->position) {
        if (e->base) 
        MASK(position)
    }
    
    // first  bit set
    
    

}
