extern void vbprintf(buffer s, sstring fmt, vlist *ap);

struct formatter_state {
    int state;
    int format;    // format character ('s', 'd', ...)
    int modifier;  // format modifier ('l')
    int width;     // format width
    int align;     // format align ('-')
    int fill;      // format fill
    int precision; // format precision
};

// make sure its safe to read more than one format char ala %02x
// if we parameterize newline we can do some nicer formatting tricks
typedef void (*formatter)(buffer dest, struct formatter_state *s, vlist *ap);
void register_format(character c, formatter f, int accepts_long);
void init_extra_prints(void);

buffer aprintf_sstring(heap h, sstring fmt, ...);
#define aprintf(h, fmt, ...)    aprintf_sstring(h, ss(fmt), ##__VA_ARGS__)

void bprintf_sstring(buffer b, sstring fmt, ...);
#define bprintf(b, fmt, ...)    bprintf_sstring(b, ss(fmt), ##__VA_ARGS__)

int rsnprintf_sstring(char *str, u64 size, sstring fmt, ...);
#define rsnprintf(str, size, fmt, ...)  rsnprintf_sstring(str, size, ss(fmt), ##__VA_ARGS__)

void rprintf_sstring(sstring format, ...);
#define rprintf(fmt, ...)   rprintf_sstring(ss(fmt), ##__VA_ARGS__)
