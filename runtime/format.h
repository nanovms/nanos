
extern void vbprintf(buffer s, buffer fmt, vlist *ap);

typedef void (*formatter)(buffer, buffer, vlist *ap);
void register_format(character c, formatter f);
// indent?

static inline buffer aprintf(heap h, char *fmt, ...)
{
    buffer b = allocate_buffer(h, 80);
    vlist ap;
    buffer f = alloca_wrap_buffer(fmt, runtime_strlen(fmt));
    vstart (ap, fmt);
    vbprintf(b, f, &ap);
    vend(ap);
    return(b);
}

static inline void bbprintf(buffer b, buffer fmt, ...)
{
    vlist ap;
    vstart(ap, fmt);
    vbprintf(b, fmt, &ap);
    vend(ap);
}

static inline void bprintf(buffer b, char *fmt, ...)
{
    vlist ap;
    buffer f = alloca_wrap_buffer(fmt, runtime_strlen(fmt));
    vstart (ap, fmt);
    vbprintf(b, f, &ap);
    vend(ap);
}


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
    vbprintf(&b, &f, &a);
    debug(&b);
}
