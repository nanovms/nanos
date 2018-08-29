#pragma once
typedef struct pqueue *pqueue;
pqueue allocate_pqueue(heap h, boolean(*)(void *, void *));
void pqueue_insert(pqueue q, void *v);
void *pqueue_peek(pqueue q);
void *pqueue_pop(pqueue q);
