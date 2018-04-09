

#define closure_type(__x, __ret, ...) __ret (**__x)(void *, ## __VA_ARGS__)

#define apply(__c, ...) (*__c)(__c, ## __VA_ARGS__)

#define closure(__h, __name, ...)\
    _fill_##__name(allocate(__h, sizeof(struct _closure_##__name)), __h, ##__VA_ARGS__)

#define continuation_name(__x) (*(char **)((void **)(__x) + 1))
  
#include <closure_templates.h>
