#include <runtime.h>

/* Debug only: Enabling TABLE_PARANOIA will perform a (costly) table
   integrity check with each affective operation. */
//#define TABLE_PARANOIA

#define EMPTY ((void *)0)
#define INITIAL_SIZE 4

boolean pointer_equal(void *a, void *b)
{
    return a == b;
}

key identity_key(void *a)
{
    return u64_from_pointer(a);
}

#ifdef TABLE_PARANOIA
#define table_paranoia(t, n)    table_validate(t, n)
#else
#define table_paranoia(t, n)
#endif

void table_validate(table t, char *n)
{
    void *last;
    for(int i = 0; i < t->buckets; i++) {
        for (entry j = t->entries[i]; last = j, j; j = j->next) {
            if (j == INVALID_ADDRESS) {
                print_stack_from_here();
                halt("table_validate fail on %s: table %p, last %p\n", n, t, last);
            }
        }
    }
}

table allocate_table(heap h, u64 (*key_function)(void *x), boolean (*equals_function)(void *x, void *y))
{
    table new = allocate(h, sizeof(struct table));
    if (new == INVALID_ADDRESS)
        return new;

    table t = tablev(new);
    t->h = h;
    t->count = 0;
    t->buckets = 4;
    t->entries = allocate_zero(h, t->buckets * sizeof(void *));
    if (t->entries == INVALID_ADDRESS) {
        deallocate(h, new, sizeof(struct table));
        return INVALID_ADDRESS;
    }
    t->key_function = key_function;
    t->equals_function = equals_function;

    /* 64-byte align for cacheline */
    t->initial_entries = allocate_align(h, sizeof(struct cv_pair) * INITIAL_SIZE, 6);
    if (t->initial_entries == INVALID_ADDRESS) {
        deallocate(h, t->entries, t->buckets * sizeof(void *));
        deallocate(h, new, sizeof(struct table));
        return INVALID_ADDRESS;
    }
    runtime_memset((void *)t->initial_entries, 0, sizeof(struct cv_pair) * INITIAL_SIZE);
    if (key_function == identity_key && equals_function == pointer_equal)
        t->use_initial = false;
    else
        t->use_initial = false;
    return new;
}

void deallocate_table(table t)
{
    table_paranoia(t, "deallocate");
    table_clear(t);
    deallocate(t->h, t->entries, t->buckets * sizeof(void *));
    deallocate_align(t->h, t->initial_entries);
    deallocate(t->h, t, sizeof(struct table));
}
KLIB_EXPORT(deallocate_table);

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
    deallocate(t->h, t->entries, t->buckets * sizeof(void *));
    t->entries = nentries;
    t->buckets = buckets;
    t->use_initial = false;
    table_paranoia(t, "resize");
}

void *table_find(table z, void *c)
{
    table t = valueof(z);
    assert(t);
    if (t->use_initial) {
        cv_pair p, pe;
        for (p = t->initial_entries, pe = p + t->count; p < pe; p++) {
            if (p->c == u64_from_pointer(c))
                return pointer_from_u64(p->v);
        }
        return EMPTY;
    }
    key k = t->key_function(c);
    for (entry i = t->entries[position(t->buckets, k)]; i; i = i->next){
        if ((i->k == k) && t->equals_function(i->c, c))
            return(i->v);
    }
    return EMPTY;
}
KLIB_EXPORT(table_find);

void table_set(table z, void *c, void *v)
{
    table t = valueof(z);
    if (t->use_initial) {
        if (v == EMPTY || t->count >= INITIAL_SIZE)
            t->use_initial = false;
        else
            t->initial_entries[t->count] =
                (struct cv_pair){u64_from_pointer(c), u64_from_pointer(v)};
    }
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
                table_paranoia(t, "remove");
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
        
        if (t->count++ > t->buckets && t->buckets <= TABLE_MAX_BUCKETS / 2) {
            resize_table(t, t->buckets*2);
        } else {
            /* resize will do a check */
            table_paranoia(t, "add, no resize");
        }
    }
}
KLIB_EXPORT(table_set);

int table_elements(table z)
{
    table t = valueof(z);
    return(t->count);
}

void table_clear(table t)
{
    for(int i = 0; i < t->buckets; i++) {
        entry e = t->entries[i];
        if (!e)
            continue;
        do {
            entry next = e->next;
            deallocate(t->h, e, sizeof(struct entry));
            e = next;
        } while (e);
        t->entries[i] = 0;
    }
    t->count = 0;
    t->use_initial = false;
}
