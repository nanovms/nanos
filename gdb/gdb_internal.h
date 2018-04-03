#include <sruntime.h>
#include <unix.h>

typedef struct handler {
    char *name;
    void *body;
} *handler;

typedef struct gdb {
    string output;
    string send_buffer;
    string out;
    string in;
    heap h; // we shouldn't use this after initialization?
    buffer_handler output_handler;
    // the suspended thread
    context registers;
    process p;
} *gdb;

static inline s8 digit_of(character x)
{
    if ((x <= 'f') && (x >= 'a')) return(x - 'a' + 10);
    if ((x <= 'F') && (x >= 'A')) return(x - 'A' + 10);
    if ((x <= '9') && (x >= '0')) return(x - '0');
    return(-1);
}

static inline char peek_char(buffer b)
{
    return(*(char *)buffer_ref(b, 0));
}

static inline char get_char(buffer b)
{
    if (buffer_length(b)) {
        char r = peek_char(b);
        buffer_consume(b, 1);
        return(r);
    } 
    return(0);
}

static inline boolean check(buffer b, char c)
{
    if (peek_char(b) == c) {
        get_char(b);
        return(true);
    }
    return(false);
}

static inline void reset_buffer(string b)
{
    b->start = 0;
    b->end = 0;
}

u64 parse_int (buffer b, u32 base, u64 *intValue);
boolean parse_hex_pair(buffer in, u64 *first, u64 *second);
boolean mem2hex (string b, void *mem, int count);
boolean hex2mem (buffer b, void *mem, int count);
void putpacket(gdb, string b);
void gdb_send(gdb, string);
void handle_query(gdb g, buffer b, string out, handler h);

