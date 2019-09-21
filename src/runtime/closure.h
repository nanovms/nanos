#pragma once

#define closure_type(__x, __ret, ...) __ret (**__x)(void *, ## __VA_ARGS__)

#define apply(__c, ...) (*__c)(__c, ## __VA_ARGS__)

#define __closure(__h, __p, __s, __name, ...)    \
    _fill_##__name(__h, __p, __s, ##__VA_ARGS__)

#define closure(__h, __name, ...)\
    __closure(__h, allocate(__h, sizeof(struct _closure_##__name)), \
              sizeof(struct _closure_##__name), __name, ##__VA_ARGS__)

#define stack_closure(__name, ...)\
    __closure(0, stack_allocate(sizeof(struct _closure_##__name)), \
              sizeof(struct _closure_##__name), __name, ##__VA_ARGS__)

void _apply_dealloc(void);

#define _apply_setup(z) \
    asm volatile("push %0" :: "r" (z)); \
    asm volatile("push %0" :: "r" (&_apply_dealloc));

struct _closure_common {
    char *name;
    heap h;
    bytes size;
};

#define return_without_dealloc                   \
    u64 discard0, discard1;                      \
    asm volatile("pop %0" : "=r" (discard0));    \
    asm volatile("pop %0" : "=r" (discard1));    \
    return

#include <closure_templates.h>
