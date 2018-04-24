#include <sruntime.h>
#include <unix.h>
#include <net_internal.h>

typedef struct gdb {
    string output;
    string send_buffer;
    string out;
    string in;
    heap h;
    u8 checksum, sent_checksum;
    buffer_handler output_handler;
    thread t; // we can really get several 
    process p;
} *gdb;

typedef struct handler {
    char *name;
    // reply
    boolean (*body)(gdb, buffer, string);
} *handler;

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
boolean handle_query(gdb g, buffer b, string out, handler h);

buffer_handler init_gdb(heap h,
                        process p,
                        buffer_handler outh);

