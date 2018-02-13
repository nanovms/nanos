#include <basic_runtime.h>


#define varg __builtin_va_arg
#define vlist __builtin_va_list
#define vstart __builtin_va_start
#define vend __builtin_va_end

typedef struct buffer *buffer;
#include <buffer.h>
#include <table.h>
#include <vector.h>
    
void debug(buffer);
void format_number(buffer s, u64 x, int base, int pad);
extern void vbprintf(buffer s, buffer fmt, vlist ap);
static inline void rprintf(char *format, ...)
{
    // fix alloca buffer support
    char t[1024];
    vlist a;
    struct buffer b;
    b.start = 0;
    b.end = 0;    
    b.contents = t;
    b.length = sizeof(t);
    
    struct buffer f;
    f.start = 0;
    f.contents = format;
    f.end = runtime_strlen(format);
    
    vstart(a, format);
    vbprintf(&b, &f, a);
    debug(&b);
}

void *load_elf(void *base, u64 offset, heap pages, heap bss);
#include <storage.h>

