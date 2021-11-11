#define closure_type(__x, __ret, ...) __ret (**__x)(void *, ## __VA_ARGS__)

#define apply(__c, ...) (*(__c))((void *)(__c), ## __VA_ARGS__)

#define async_apply(__t, __c, ...) async_apply_##__t(__c, ## __VA_ARGS__)

#define __closure(__c, __p, __s, __name, ...)    \
    _fill_##__name(__c, __p, __s, ##__VA_ARGS__)

#define ctx_from_heap(__h) (u64_from_pointer(__h) | CLOSURE_COMMON_CTX_DEALLOC_ON_FINISH)

#define closure_alloc(__h, __name, __var)   do {                \
    __var = allocate(__h, sizeof(struct _closure_##__name));    \
    if (__var != INVALID_ADDRESS) {                             \
        __var->__apply = __name;                                \
        __var->__c.name = #__name;                              \
        __var->__c.ctx = ctx_from_heap(__h);                    \
        __var->__c.size = sizeof(struct _closure_##__name);     \
    }                                                           \
} while (0);

struct _closure_common {
    char *name;
#define CLOSURE_COMMON_CTX_IS_CONTEXT        1 /* vs heap */
#define CLOSURE_COMMON_CTX_DEALLOC_ON_FINISH 2
#define CLOSURE_COMMON_CTX_FLAGS_MASK        3
    u64 ctx;
    bytes size;
    void *context;
};

#define closure_new(__h, __name, __var) \
    struct _closure_##__name *__var;   \
    closure_alloc(__h, __name, __var)

#define closure(__h, __name, ...) ({                                    \
    struct _closure_##__name * __n = allocate(__h, sizeof(struct _closure_##__name)); \
    __closure(ctx_from_heap(__h), __n, sizeof(struct _closure_##__name), __name, ##__VA_ARGS__);})

#define stack_closure(__name, ...)                                 \
    __closure(0, stack_allocate(sizeof(struct _closure_##__name)), \
              sizeof(struct _closure_##__name), __name, ##__VA_ARGS__)

#define init_closure(__p, __name, ...)                                  \
    __closure(0, (__p), sizeof(struct _closure_##__name), __name, ##__VA_ARGS__)

#define closure_struct(__name, __field) struct _closure_##__name __field;

#define closure_ref(__name, __var) struct _closure_##__name *__var = 0;

#define __closure_struct_declare(nl, nr) CLOSURE_STRUCT_ ## nl ## _ ## nr
#define __closure_function_declare(nl, nr) CLOSURE_DECLARE_FUNCS_ ## nl ## _ ## nr
#define __closure_define(nl, nr) CLOSURE_DEFINE_ ## nl ## _ ## nr
#define __closure_simple_define(nl, nr) CLOSURE_SIMPLE_DEFINE_ ## nl ## _ ## nr

#define closure_function(nl, nr, ...)                   \
    __closure_struct_declare(nl, nr)(__VA_ARGS__)       \
    __closure_function_declare(nl, nr)(__VA_ARGS__)     \
    __closure_define(nl, nr)(__VA_ARGS__)

/* use these for closures embedded within structs */
#define declare_closure_struct(nl, nr, ...) __closure_struct_declare(nl, nr)(__VA_ARGS__)
#define declare_closure_function(nl, nr, ...)           \
    __closure_struct_declare(nl, nr)(__VA_ARGS__)       \
    __closure_function_declare(nl, nr)(__VA_ARGS__)
#define define_closure_function(nl, nr, ...)            \
    __closure_function_declare(nl, nr)(__VA_ARGS__)     \
    __closure_define(nl, nr)(__VA_ARGS__)

/* use this for closures allocated and filled separately */
#define simple_closure_function(nl, nr, ...)            \
    __closure_struct_declare(nl, nr)(__VA_ARGS__)       \
    __closure_simple_define(nl, nr)(__VA_ARGS__)
#define closure_get(name, var)  ((name##_func)&(var->__apply))

#define bound(v) (__self->v)
#define closure_self() (&(__self->__apply))
#define closure_member(name, var, member)   ((struct _closure_##name *)(var))->member

#include <closure_templates.h>
