#include <runtime.h>

void initialize_buffer();

static inline CLOSURE_0_0(ignore_body, void);
static inline void ignore_body(){}
thunk ignore;
status_handler ignore_status;

static void format_buffer(buffer dest, buffer fmt, vlist ap)
{
    push_buffer(dest, varg(ap, buffer));
}

// init linker sets would clean up the platform dependency, if you link
// with it, it gets initialized
void init_runtime(heap h)
{
    init_tuples(allocate_tagged_region(h, tag_tuple));
    init_symbols(allocate_tagged_region(h, tag_symbol));
#ifndef BITS32    
    initialize_timers(h);
#endif    
    ignore = closure(h, ignore_body);
    ignore_status = (void*)ignore;
    // come up with a better decomposition
#ifndef BITS32    
    register_format('b', format_buffer);
#endif    
}

