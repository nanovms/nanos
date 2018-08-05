
extern void vbprintf(buffer s, buffer fmt, vlist *ap);

// make sure its safe to read more than one format char ala %02x
// if we parameterize newline we can do some nicer formatting tricks
typedef void (*formatter)(buffer dest, buffer fmt, vlist *ap);
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
    vlist a;    
    buffer b = allocate_buffer(transient, 64);
    // fix alloca buffer support
    // buffer b = little_stack_buffer(1024);
    
    struct buffer f;
    f.start = 0;
    f.contents = format;
    f.end = runtime_strlen(format);

    vstart(a, format);
    vbprintf(b, &f, &a);
    debug(b);
}
