#include <runtime.h>

#define EMPTY ((void *)0)

table allocate_table(heap h, u64 (*key_function)(void *x), boolean (*equals_function)(void *x, void *y))
{
    table new = allocate(h, sizeof(struct table));
    table t = valueof(new);
    t->h = h;
    t->count = 0;
    t->buckets = 64;
    t->entries = allocate_zero(t->h, t->buckets * sizeof(void *));    
    t->key_function = key_function;
    t->equals_function = equals_function;
    return(new);
}

static inline key position(int buckets, key x)
{
    return(x&(buckets-1));
}


void *table_find (table z, void *c)
{
    table t = valueof(z);
    key k = t->key_function(c);

    for (entry i = t->entries[position(t->buckets, k)]; i; i = i->next){
        if ((i->k == k) && t->equals_function(i->c, c))
            return(i->v);
    }
    return(EMPTY);
}

static void resize_table(table z, int buckets)
{
    table t = valueof(z);
    entry *nentries = allocate_zero(t->h, buckets * sizeof(void *));        

    for(int i = 0; i<t->buckets; i++){
        entry j = t->entries[i];
        while(j) {
            entry n = j->next;
            key km = position(buckets, j->k);
            j->next = nentries[km];
            nentries[km] = j;
            j = n;
        }
    }
    t->entries = nentries;
    t->buckets = buckets;
}


void table_set (table z, void *c, void *v)
{
    table t = valueof(z);
    key k = t->key_function(c);
    key p = position(t->buckets, k);
    entry *e = t->entries + p;
    
    for (; *e; e = &(*e)->next)
        if (((*e)->k == k) && t->equals_function((*e)->c, c)) {
            if (v == EMPTY) {
                t->count--;
                entry z = *e;
                *e = (*e)->next;
                deallocate(t->h, z, sizeof(struct entry));
            } else (*e)->v = v;
            return;
        }

    if (v != EMPTY) {
        entry n = allocate(t->h, sizeof(struct entry));

        n->k = k;
        n->c = c; 
        n->v = v;
        n->next = 0;
        *e = n;
        
        if (t->count++ > t->buckets) 
            resize_table(t, t->buckets*2);
    }
}

int table_elements(table z)
{
    table t = valueof(z);
    return(t->count);
}
