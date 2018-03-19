
typedef struct handler {
  char *name;
  void *body;
} *handler;


static inline char peek_char(buffer b)
{
    return(*(char *)buffer_reference(b, 0));
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

u32 parse_int (buffer b, u32 base, u32 *intValue);
boolean parse_hex_pair(buffer in, u32 *first, u32 *second);
boolean mem2hex (string b, void *mem, int count);
boolean hex2mem (buffer b, void *mem, int count);
void putpacket(string sendbuffer, string b);
void gdb_send(string s);
void handle_query(buffer b, string out, handler h);
