#include <runtime.h>
#include <x86_64.h>
#include <elf64.h>
#include <closure.h>
#include <closure_templates.h>

typedef closure_type(buffer_handler, void, buffer);
typedef closure_type(thunk, void);

#if 0
static node resolve(buffer n, symbol s)
{
}

static vector node_vector(heap h, buffer n)
{
    vector r = allocate_vector(h, 100); //table_elements(n));
    little_stack_buffer (ind, 30);
    void *x;
    
    for (int i = 0; format_number(ind, i, 10, 1), x = resolve(n, intern(ind)); buffer_clear(ind), i++) 
        vector_push(r, x);
    
    return x;
}
#endif

static tuple resolve_path(tuple n, vector v)
{
    buffer i;
    // xx destructive, relative
    vector_pop(v);
    vector_foreach(i, v) {
        tuple c = table_find(n, sym(children));
        n = table_find(c, intern(i));
    }
    return n;
}

static inline table children(table x)
{
    return table_find(x, sym(children));
}

static inline buffer contents(table x)
{
    return table_find(x, sym(contents));
}

static inline tuple lookup_step(tuple t, buffer a)
{
    void *c = children(t);
    if (!c) return c;
    return table_find(c, intern(a));
}


// fused buffer wrap, split, and resolve
static inline tuple resolve_cstring(tuple root, char *f)
{
    little_stack_buffer(a, 50);
    char *x = f;
    tuple t = root;
    char y;

    while (y = *x++) {
        if (y == '/') {
            if (buffer_length(a)) {
                t = lookup_step(t, a);
                if (!t) return t;
                buffer_clear(a);
            }                
        } else {
            push_character(a, y);
        }
    }
    if (buffer_length(a)) t = lookup_step(t, a);
    return t;
}


void bprintf(buffer b, char *fmt, ...);
// belongs somewhere else?
void storage_read(void *target, u64 offset, u64 size, thunk complete);


static inline void haltf(char *f, ...)
{
    buffer bf = alloca_wrap_buffer(f, runtime_strlen(f));
    little_stack_buffer(b, 2048);
    vlist ap;
    vstart (ap, f);
    vbprintf(b, bf,  ap);
    debug(b->contents);
    QEMU_HALT();
}

// xxx - platform features that use closures in stage3 that cant
// be exposed to stage2...a middle layer
typedef closure_type(fault_handler, u64 *, context);
void configure_timer(time rate, thunk t);
void enqueue(queue q, thunk n);
thunk dequeue(queue q);
queue allocate_queue(heap h, u64 size);
void runloop();
