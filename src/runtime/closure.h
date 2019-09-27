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

struct _closure_common {
    char *name;
    heap h;
    bytes size;
};

#define bound(name) (__self->name)
#define __closure_name(nl, nr) CLOSURE_ ## nl ## _ ## nr
#define define_closure(nl, nr, ...) __closure_name(nl, nr)(__VA_ARGS__)

#include <closure_templates.h>
