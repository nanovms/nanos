#include <runtime.h>

#define EMPTY ((void *)0)

static void allocate_buckets(table t)
{
    t->entries = allocate_zero(t->h, t->buckets * sizeof(void *));
}

table allocate_table(heap h, u64 (*key_function)(void *x), boolean (*equals_function)(void *x, void *y))
{
    table new = allocate(h, sizeof(struct table));
    new->h = h;
    new->count = 0;
    new->buckets = 4;
    allocate_buckets(new);
    new->key_function = key_function;
    new->equals_function = equals_function;
    return(new);
}

static inline key position(table t, key x)
{
    return(x&(t->buckets-1));
}


void *table_find (table z, void *c)
{
    table t = valueof(z);
    key k = t->key_function(c);

    for (entry i = t->entries[position(t, k)];
         i; i = i->next)
        if ((i->k == k) && t->equals_function(i->c, c))
            return(i->v);

    return(EMPTY);
}

void *table_find_key (table t, void *c, void **kr)
{
    key k = t->key_function(c);

    for (entry i = t->entries[position(t, k)];
         i; i = i->next)
        if ((i->k == k) && t->equals_function(i->c, c)){
            *kr = i->c;
            return(i->v);
        }

    return(EMPTY);
}


static void resize_table(table t, int buckets)
{
    entry *old_entries = t->entries;
    key km;
    int old_buckets = t->buckets;

    t->buckets = buckets;
    allocate_buckets(t);

    for(int i = 0; i<old_buckets; i++){
        entry j = old_entries[i];
        
        while(j) {
            entry n = j->next;
            km = position(t, j->k);
            j->next = t->entries[km];
            t->entries[km] = j;
            j = n;
        }
    }
}


void table_set (table z, void *c, void *v)
{
    table t = valueof(z);
    key k = t->key_function(c);
    key p = position(t, k);
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
