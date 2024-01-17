#include <runtime.h>

struct formatter {
	formatter f;
	int accepts_long;
};

BSS_RO_AFTER_INIT static struct formatter formatters[96];
#define FORMATTER(c) (formatters[c - 32])

void register_format(character c, formatter f, int accepts_long)
{
    assert(c != 'l'); // reserved

    if ((c > 32) && (c < 128)) {
        FORMATTER(c).f = f;
        FORMATTER(c).accepts_long = accepts_long;
    }
}

static void invalid_format(buffer d, sstring fmt, int start_idx, int idx)
{
    static const char header[] = "[invalid format ";

    assert(buffer_write(d, header, sizeof(header) - 1));
    for (int i = 0; i < idx - start_idx + 1; i++)
        push_u8(d, fmt.ptr[start_idx + i]);
    push_u8(d, ']');
}

static void reset_formatter_state(struct formatter_state *s)
{
    s->state = 0;
    s->format = 0;
    s->modifier = 0;
    s->width = 0;
    s->align = 0;
    s->fill = 0;
    s->precision = -1;
}

void vbprintf(buffer d, sstring fmt, vlist *ap)
{
    int start_idx = 0;
    struct formatter_state s;

    reset_formatter_state(&s);
    sstring_foreach(idx, c, fmt) {
        if (s.state == 1)  {
            if (idx - start_idx == 1 && (c == '0' || c == '-')) {
                if (c == '0')
                    s.fill = '0';
                else if (c == '-')
                    s.align = '-';
                continue;
            }
            if ((c >= '0') && (c <= '9')) {
                if (s.precision == -1) {
                    if (!s.fill)
                        s.fill = ' ';
                    s.width = s.width * 10 + c - '0';
                } else
                    s.precision = s.precision * 10 + c - '0';
            } else if (c == 'l') {
                if (s.modifier != 0)
                    invalid_format(d, fmt, start_idx, idx);
                else
                    s.modifier = c;
            } else if (c == '%') {
                push_character(d, c);
                s.state = 0;
            } else if (c == '.') {
                if (s.precision != -1)
                    invalid_format(d, fmt, start_idx, idx);
                else
                    s.precision = 0;
            } else {
                if ((c > 32) && (c < 128) &&
                    FORMATTER(c).f &&
                    (s.modifier != 'l' || FORMATTER(c).accepts_long)) {
                    s.format = c;
                    FORMATTER(c).f(d, &s, ap);
                } else {
                    invalid_format(d, fmt, start_idx, idx);
                }

                reset_formatter_state(&s);
            }
        } else {
            if ((s.state == 0) && (c == '%')) {
                s.state = 1;
                start_idx = idx;
            } else {
                push_character(d, c);
            }
        }
    }
}

// XXX fixme
/* XXX the various debug stuff needs to be folded into one log facility...somewhere */
void log_vprintf(sstring prefix, sstring log_format, vlist *a)
{
    buffer b = little_stack_buffer(1024);
    bprintf(b, "[%T] %s: ", now(CLOCK_ID_BOOTTIME), prefix);
    vbprintf(b, log_format, a);
    buffer_print(b);
}

void log_printf(sstring prefix, sstring log_format, ...)
{
    vlist a;
    vstart(a, log_format);
    log_vprintf(prefix, log_format, &a);
}

buffer aprintf_sstring(heap h, sstring fmt, ...)
{
    buffer b = allocate_buffer(h, 80);
    vlist ap;
    vstart (ap, fmt);
    vbprintf(b, fmt, &ap);
    vend(ap);
    return(b);
}

void bprintf_sstring(buffer b, sstring fmt, ...)
{
    vlist ap;
    vstart (ap, fmt);
    vbprintf(b, fmt, &ap);
    vend(ap);
}

int rsnprintf_sstring(char *str, u64 size, sstring fmt, ...)
{
    buffer b = allocate_buffer(transient, size);
    if (b == INVALID_ADDRESS) {
        msg_err("buffer allocation failed\n");
        if (size > 0)
            str[0] = '\0';
        return 0;
    }
    vlist ap;
    vstart(ap, fmt);
    vbprintf(b, fmt, &ap);
    vend(ap);
    int n;
    if (size > 0) {
        n = MIN(buffer_length(b), size - 1);
        runtime_memcpy(str, buffer_ref(b, 0), n);
        str[n] = '\0';
    }
    n = buffer_length(b);
    deallocate_buffer(b);
    return n;
}

void rprintf_sstring(sstring format, ...)
{
    /* What's a reasonable limit here? This needs to be reentrant. */
    buffer b = little_stack_buffer(16 * KB);
    vlist a;
    vstart(a, format);
    vbprintf(b, format, &a);
    buffer_print(b);
}
