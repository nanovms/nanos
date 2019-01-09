#include <runtime.h>

#define EMPTY ((void *)0)
#define MIN_BUCKET_SIZE 4

void table_check(table t, char *n)
{
    void *last;
    for(int i = 0; i<t->buckets; i++){
        entry j = t->entries[i];
        last = j;
        while(j) {
            if (j == INVALID_ADDRESS) {
                rprintf("badness 8000 %p %s %p\n", t, n, last);
                rprintf("build: %p\n", __builtin_return_address(1));
                halt("zig why no format");
            }
            last = j;
            j = j->next;
        }
    }
}


table allocate_table(heap h, u64 (*key_function)(void *x), boolean (*equals_function)(void *x, void *y))
{
    bytes table_size = sizeof(struct table);
    table new = allocate(h, table_size);
    if (new == INVALID_ADDRESS) halt("allocate table failed\n");
    table t = tablev(new);
    t->h = h;
    t->h->allocated += table_size;
    t->count = 0;
    t->buckets = MIN_BUCKET_SIZE;
    bytes entries_size = t->buckets * sizeof(void *);
    t->entries = allocate_zero(h, entries_size);
    t->h->allocated += entries_size;
    t->key_function = key_function;
    t->equals_function = equals_function;
    return(new);
}

void deallocate_table(table t) {
  bytes entries_size = t->buckets * sizeof(void *);
  bytes table_size = sizeof(struct table);
  t->h->allocated -= entries_size + table_size;
  deallocate(t->h, t->entries, entries_size);
  deallocate(t->h, t, table_size);
}

static inline key position(int buckets, key x)
{
    return(x&(buckets-1));
}


void *table_find (table z, void *c)
{
    table t = valueof(z);
    assert(t);
    key k = t->key_function(c);
    for (entry i = t->entries[position(t->buckets, k)]; i; i = i->next){
        if ((i->k == k) && t->equals_function(i->c, c))
            return(i->v);
    }
    return(EMPTY);
}


static void resize_table(table z, int buckets)
{
    if(buckets < MIN_BUCKET_SIZE)
        buckets = MIN_BUCKET_SIZE;
    table t = valueof(z);
    bytes entries_size = buckets * sizeof(void *);
    entry *nentries = allocate_zero(t->h, entries_size);
    t->h->allocated += entries_size;
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
    entries_size = t->buckets * sizeof(void *);
    deallocate(t->h, t->entries, t->buckets * sizeof(void *));
    t->h->allocated -= entries_size;
    t->entries = nentries;
    t->buckets = buckets;
    table_check(t, "resize");
}

void table_set (table z, void *c, void *v)
{
    table t = valueof(z);
    //    rprintf("set: %p %p %p\n", z, t->entries, __builtin_return_address(0));
    key k = t->key_function(c);
    key p = position(t->buckets, k);
    entry *e = t->entries + p;
    for (; *e; e = &(*e)->next) {
        if (((*e)->k == k) && t->equals_function((*e)->c, c)) {
            if (v == EMPTY) {
                t->count--;
                entry z = *e;
                *e = (*e)->next;
                table_check(t, "remove");
                bytes entry_size = sizeof(struct entry);
                deallocate(t->h, z, entry_size);
                t->h->allocated -= entry_size;
                if(t->count < (t->buckets/2))
                    resize_table(t, t->buckets/2);
            } else (*e)->v = v;
            return;
        }
    }

    if (v != EMPTY) {
        // xxx - shouldnt need to zero - messing about
        bytes entry_size = sizeof(struct entry);
        entry n = valueof(allocate_zero(t->h, entry_size));
        t->h->allocated += entry_size;

        if (n == INVALID_ADDRESS) {
            halt("couldn't allocate table entry\n");
        }

        n->k = k;
        n->c = c; 
        n->v = v;
        *e = n;
        
        if (t->count++ > t->buckets) 
            resize_table(t, t->buckets*2);
    }
    else if(t->count < (t->buckets/2)) {
        resize_table(t, t->buckets/2);
    }
}

int table_elements(table z)
{
    table t = valueof(z);
    return(t->count);
}
