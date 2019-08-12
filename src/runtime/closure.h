#pragma once

#define closure_type(__x, __ret, ...) __ret (**__x)(void *, ## __VA_ARGS__)

#define apply(__c, ...) (*__c)(__c, ## __VA_ARGS__)

#define __closure(__p, __name, ...)\
    _fill_##__name(__p, ##__VA_ARGS__)

#define closure(__h, __name, ...)\
    __closure(allocate(__h, sizeof(struct _closure_##__name)), __name, ##__VA_ARGS__)

#define stack_closure(__name, ...)\
    __closure(stack_allocate(sizeof(struct _closure_##__name)), __name, ##__VA_ARGS__)

#include <closure_templates.h>
