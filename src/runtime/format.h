extern void vbprintf(buffer s, buffer fmt, vlist *ap);

extern void log_vprintf(const char *prefix, const char *log_format, vlist *a);
extern void log_printf(const char *prefix, const char *log_format, ...);

struct formatter_state {
    int state;
    int format;    // format character ('s', 'd', ...)
    int modifier;  // format modifier ('l')
    int width;     // format width
};

// make sure its safe to read more than one format char ala %02x
// if we parameterize newline we can do some nicer formatting tricks
typedef void (*formatter)(buffer dest, struct formatter_state *s, vlist *ap);
void register_format(character c, formatter f, int accepts_long);
void init_extra_prints(void);

buffer aprintf(heap h, const char *fmt, ...);
void bbprintf(buffer b, buffer fmt, ...);
void bprintf(buffer b, const char *fmt, ...);
void rprintf(const char *format, ...);
