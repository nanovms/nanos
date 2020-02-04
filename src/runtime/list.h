typedef struct list {
    struct list * prev;
    struct list * next;
} *list;

#define struct_from_list(l, s, f) ((s)pointer_from_u64(u64_from_pointer(l) - offsetof(s, f)))
#define list_foreach(l, e) \
    for (list __next, e = list_begin(l); __next = e->next, e != list_end(l); e = __next)

static inline void list_init(struct list * head)
{
    head->prev = head->next = head;
}

static inline boolean list_empty(struct list * head)
{
    assert(((head->next == head) ^ (head->prev == head)) == 0);

    return (head->next == head);
}

/* XXX fix, this isn't used right */
static inline struct list * list_get_next(struct list * head)
{
    return head->next == head ? 0 : head->next;
}

static inline void list_delete(struct list * p)
{
    assert(p->prev && p->next);
    p->prev->next = p->next;
    p->next->prev = p->prev;
    p->prev = p->next = 0;
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

static inline struct list *list_begin(struct list *head)
{
    return head->next;
}

static inline struct list *list_end(struct list  *head)
{
    return head;
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
