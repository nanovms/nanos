#include <runtime.h>

#define EMPTY ((void *)0)

boolean pointer_equal(void *a, void *b)
{
    return a == b;
}

key identity_key(void *a)
{
    return u64_from_pointer(a);
}

/* TODO: Make optional for production */
void table_check(table t, char *n)
{
    void *last;
    for(int i = 0; i < t->buckets; i++) {
        for (entry j = t->entries[i]; last = j, j; j = j->next) {
            if (j == INVALID_ADDRESS) {
                print_stack_from_here();
                halt("table_check fail on %s: table %p, last %p\n", n, t, last);
            }
        }
    }
}

table allocate_table(heap h, u64 (*key_function)(void *x), boolean (*equals_function)(void *x, void *y))
{
    table new = allocate(h, sizeof(struct table));
    if (new == INVALID_ADDRESS)
        goto alloc_fail;

    table t = tablev(new);
    t->h = h;
    t->count = 0;
    t->buckets = 4;
    t->entries = allocate_zero(h, t->buckets * sizeof(void *));
    if (t->entries == INVALID_ADDRESS)
        goto alloc_fail;
    t->key_function = key_function;
    t->equals_function = equals_function;
    return new;

  alloc_fail:
    halt("allocation failure in allocate_table\n");
}

static inline key position(int buckets, key x)
{
    return x & (buckets-1);
}

static void resize_table(table z, int buckets)
{
    assert((buckets & (buckets - 1)) == 0);
    assert(buckets <= TABLE_MAX_BUCKETS);
    table t = valueof(z);
    entry *nentries = allocate_zero(t->h, buckets * sizeof(void *));
    if (nentries == INVALID_ADDRESS)
        halt("resize_table: allocate fail for %d buckets\n", buckets);
    for (int i = 0; i < t->buckets; i++) {
        for (entry n, j = t->entries[i]; j; j = n) {
            n = j->next;
            key km = position(buckets, j->k);
            j->next = nentries[km];
            nentries[km] = j;
        }
    }
    t->entries = nentries;
    t->buckets = buckets;
    table_check(t, "resize");
}

void *table_find(table z, void *c)
{
    table t = valueof(z);
    assert(t);
    key k = t->key_function(c);
    for (entry i = t->entries[position(t->buckets, k)]; i; i = i->next){
        if ((i->k == k) && t->equals_function(i->c, c))
            return(i->v);
    }
    return EMPTY;
}

void table_set(table z, void *c, void *v)
{
    table t = valueof(z);
    key k = t->key_function(c);
    key p = position(t->buckets, k);
    entry *e = t->entries + p;
    for (; *e; e = &(*e)->next) {
        if (((*e)->k == k) && t->equals_function((*e)->c, c)) {
            if (v == EMPTY) {
                assert(t->count > 0);
                t->count--;
                entry z = *e;
                *e = (*e)->next;
                table_check(t, "remove");
                deallocate(t->h, z, sizeof(struct entry));
            } else {
                (*e)->v = v;
            }
            return;
        }
    }

    if (v != EMPTY) {
        entry n = valueof(allocate(t->h, sizeof(struct entry)));
        if (n == INVALID_ADDRESS)
            halt("couldn't allocate table entry\n");

        n->v = v;
        n->k = k;
        n->c = c;
        n->next = 0;
        *e = n;
        
        if (t->count++ > t->buckets && t->buckets < TABLE_MAX_BUCKETS / 2)
            resize_table(t, t->buckets*2);
    }
}

int table_elements(table z)
{
    table t = valueof(z);
    return(t->count);
}
