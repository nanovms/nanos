#include <runtime.h>

struct formatter {
	formatter f;
	int accepts_long;
};

static struct formatter formatters[96];
#define FORMATTER(c) (formatters[c - 32])

void register_format(character c, formatter f, int accepts_long)
{
    assert(c != 'l'); // reserved

    if ((c > 32) && (c < 128)) {
        FORMATTER(c).f = f;
        FORMATTER(c).accepts_long = accepts_long;
    }
}

static void invalid_format(buffer d, buffer fmt, int start_idx, int idx)
{
    static char header[] = "[invalid format ";

    buffer_write(d, header, sizeof(header) - 1);
    for (int i = 0; i < idx - start_idx + 1; i++)
        push_u8(d, byte(fmt, start_idx + i));
    push_u8(d, ']');
}

static void reset_formatter_state(struct formatter_state *s)
{
    s->state = 0;
    s->format = 0;
    s->modifier = 0;
    s->width = 0;
}

void vbprintf(buffer d, buffer fmt, vlist *ap)
{
    int start_idx = 0;
    struct formatter_state s;

    reset_formatter_state(&s);
    foreach_character(idx, c, fmt) {
        if (s.state == 1)  {
	    if ((c >= 48) && (c <= 57)) {
		s.width = s.width * 10 + c - 48;
	    } else if (c == 'l') {
                if (s.modifier != 0)
                    invalid_format(d, fmt, start_idx, idx);
                else
                    s.modifier = c;
        } else if (c == '%') {
            push_character(d, c);
            s.state = 0;
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

/* XXX the various debug stuff needs to be folded into one log facility...somewhere */
void log_vprintf(const char *prefix, const char *log_format, vlist *a)
{
    buffer b = little_stack_buffer(1024);
    bprintf(b, "[%T] %s: ", now(CLOCK_ID_BOOTTIME), prefix);
    buffer f = alloca_wrap_buffer(log_format, runtime_strlen(log_format));
    vbprintf(b, f, a);
    buffer_print(b);
}

void log_printf(const char * prefix, const char *log_format, ...)
{
    vlist a;
    vstart(a, log_format);
    log_vprintf(prefix, log_format, &a);
}

buffer aprintf(heap h, const char *fmt, ...)
{
    buffer b = allocate_buffer(h, 80);
    vlist ap;
    buffer f = alloca_wrap_buffer(fmt, runtime_strlen(fmt));
    vstart (ap, fmt);
    vbprintf(b, f, &ap);
    vend(ap);
    return(b);
}

void bbprintf(buffer b, buffer fmt, ...)
{
    vlist ap;
    vstart(ap, fmt);
    vbprintf(b, fmt, &ap);
    vend(ap);
}

void bprintf(buffer b, const char *fmt, ...)
{
    vlist ap;
    buffer f = alloca_wrap_buffer(fmt, runtime_strlen(fmt));
    vstart (ap, fmt);
    vbprintf(b, f, &ap);
    vend(ap);
}


void rprintf(const char *format, ...)
{
    /* What's a reasonable limit here? This needs to be reentrant. */
    buffer b = little_stack_buffer(1024);
    vlist a;
    vstart(a, format);
    buffer f = alloca_wrap_buffer(format, runtime_strlen(format));
    vbprintf(b, f, &a);
    buffer_print(b);
}
