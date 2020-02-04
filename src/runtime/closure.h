#define closure_type(__x, __ret, ...) __ret (**__x)(void *, ## __VA_ARGS__)

#define apply(__c, ...) (*(__c))((void *)(__c), ## __VA_ARGS__)

#define __closure(__h, __p, __s, __name, ...)    \
    _fill_##__name(__h, __p, __s, ##__VA_ARGS__)

#define closure(__h, __name, ...) ({                                    \
    struct _closure_##__name * __n = allocate(__h, sizeof(struct _closure_##__name)); \
    __closure(__h, __n, sizeof(struct _closure_##__name), __name, ##__VA_ARGS__);})

#define stack_closure(__name, ...)                                 \
    __closure(0, stack_allocate(sizeof(struct _closure_##__name)), \
              sizeof(struct _closure_##__name), __name, ##__VA_ARGS__)

#define init_closure(__p, __name, ...)                                  \
    __closure(0, (__p), sizeof(struct _closure_##__name), __name, ##__VA_ARGS__)

#define closure_struct(__name, __field) struct _closure_##__name __field;

struct _closure_common {
    char *name;
    heap h;
    bytes size;
};

#define __closure_struct_declare(nl, nr) CLOSURE_STRUCT_ ## nl ## _ ## nr
#define __closure_function_declare(nl, nr) CLOSURE_DECLARE_FUNCS_ ## nl ## _ ## nr
#define __closure_define(nl, nr) CLOSURE_DEFINE_ ## nl ## _ ## nr

#define closure_function(nl, nr, ...)                   \
    __closure_struct_declare(nl, nr)(__VA_ARGS__)       \
    __closure_function_declare(nl, nr)(__VA_ARGS__)     \
    __closure_define(nl, nr)(__VA_ARGS__)

/* use these for closures embedded within structs */
#define declare_closure_struct(nl, nr, ...) __closure_struct_declare(nl, nr)(__VA_ARGS__)
#define declare_closure_function(nl, nr, ...) __closure_function_declare(nl, nr)(__VA_ARGS__)
#define define_closure_function(nl, nr, ...)            \
    __closure_function_declare(nl, nr)(__VA_ARGS__)     \
    __closure_define(nl, nr)(__VA_ARGS__)

#define bound(v) (__self->v)
#define closure_self() (&(__self->__apply))

/* XXX type safety, possibly tag */
static inline void deallocate_closure(void *p)
{
    struct _closure_common *c = p + sizeof(void *); /* skip __apply */
    if (c->h && c->size > 0)
        deallocate(c->h, p, c->size);
}

#define closure_finish() do { deallocate_closure(__self); __self = 0; } while(0)

#include <closure_templates.h>
