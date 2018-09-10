#pragma once
typedef struct list {
    struct list * prev;
    struct list * next;
} *list;

#define struct_from_list(l, s, f) ((s)pointer_from_u64(u64_from_pointer(l) - offsetof(s, f)))

static inline void list_init(struct list * head)
{
    head->prev = head->next = head;
}

static inline boolean list_empty(struct list * head)
{
    assert((head->next == head) ^ (head->prev == head) == 0);
    return (head->next == head);
}

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
