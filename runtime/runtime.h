// merge basic runtime - no one uses it anymore
#include <basic_runtime.h>

#define varg __builtin_va_arg
#define vlist __builtin_va_list
#define vstart __builtin_va_start
#define vend __builtin_va_end

#define alloca __builtin_alloca

typedef struct buffer *buffer;
typedef struct buffer *string;

void format_number(buffer s, u64 x, int base, int pad);

#include <table.h>
#include <text.h>
#include <vector.h>

typedef buffer string;

buffer aprintf(heap h, char *fmt, ...);
void debug(buffer);
void format_number(buffer s, u64 x, int base, int pad);
extern void vbprintf(buffer s, buffer fmt, vlist ap);
void bprintf(buffer b, char *fmt, ...);

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

static inline boolean compare_bytes(void *a, void *b, bytes len)
{
    for (int i = 0; i < len ; i++) {
        if (((u8 *)a)[i] != ((u8 *)b)[i])
            return false;
    }
    return true;
}


#include <symbol.h>

typedef table node;
#include <storage.h>
typedef table tuple;
#include <closure.h>
#include <closure_templates.h>
typedef closure_type(buffer_handler, void, buffer);
typedef closure_type(thunk, void);
#include <pqueue.h>
#include <timer.h>


// break out platform
#include <x86_64.h>

// just take a buffer or a tuple?
extern void halt(char *format, ...);

// should be  (parser, parser, character)
typedef closure_type(parser, void *, character);
// textual? semantic
typedef closure_type(parse_error, void, buffer);
typedef closure_type(parse_finish, void, void *);
parser tuple_parser(heap h, parse_finish c, parse_error err);
parser parser_feed (parser p, buffer b);
    
