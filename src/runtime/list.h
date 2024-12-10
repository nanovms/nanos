typedef struct list {
    struct list * prev;
    struct list * next;
} *list;

#define struct_from_list(l, s, f) struct_from_field(l, s, f)
#define list_foreach(l, e) \
    for (list __next, e = list_begin(l); __next = e->next, e != list_end(l); e = __next)
#define list_foreach_reverse(l, e) \
    for (list __next, e = (l)->prev; __next = e->prev, e != (l); e = __next)

static inline void list_init(struct list * head)
{
    head->prev = head->next = head;
}

static inline void list_init_member(struct list * p)
{
    p->prev = p->next = 0;
}

static inline boolean list_empty(struct list * head)
{
#ifndef KLIB
    assert(((head->next == head) ^ (head->prev == head)) == 0);
#endif
    return (head->next == head);
}

/* a singular list is a list containing a single element */
static inline boolean list_singular(struct list *head)
{
    return (head->next != head) && (head->next == head->prev);
}

/* XXX fix, this isn't used right */
static inline struct list * list_get_next(struct list * head)
{
    return head->next == head ? 0 : head->next;
}

static inline void list_delete(struct list * p)
{
#ifndef KLIB
    assert(p->prev && p->next);
#endif
    p->prev->next = p->next;
    p->next->prev = p->prev;
    p->prev = p->next = 0;
}

static inline boolean list_inserted(struct list * p)
{
    return p->next != 0;
}

static inline void list_insert_after(struct list * pos,
                     struct list * new)
{
    new->prev = pos;
    new->next = pos->next;
    pos->next->prev = new;
    pos->next = new;
}

static inline void list_insert_before(struct list * pos,
                      struct list * new)
{
    new->prev = pos->prev;
    new->next = pos;
    pos->prev->next = new;
    pos->prev = new;
}

static inline void list_replace(struct list *old, struct list *new)
{
    new->next = old->next;
    new->next->prev = new;
    new->prev = old->prev;
    new->prev->next = new;
}

static inline struct list *list_begin(struct list *head)
{
    return head->next;
}

static inline struct list *list_end(struct list  *head)
{
    return head;
}

static inline void list_push(struct list *list, struct list *elem)
{
    list_insert_after(list_end(list), elem);
}

static inline struct list *list_pop(struct list *list)
{
    struct list *first = list_begin(list);
    list_delete(first);
    return first;
}

static inline void list_push_back(struct list *list, struct list *elem)
{
    list_insert_before(list_end(list), elem);
}

static inline struct list *list_pop_back(struct list *list)
{
    struct list *back = list_end(list)->prev;
    list_delete(back);
    return back;
}

static inline boolean list_find(struct list *head, struct list *elem)
{
    list_foreach(head, e) {
        if (e == elem)
            return true;
    }
    return false;
}

/* Move all elements from source list to destination list. */
static inline void list_move(struct list *dest, struct list *src)
{
    if (list_empty(src)) {
        list_init(dest);
        return;
    }
    list_replace(src, dest);
    list_init(src); /* make it an empty list */
}
