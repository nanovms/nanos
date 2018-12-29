#include <runtime.h>

static formatter formatters[96]={0};

void register_format(character c, formatter f)
{
    if ((c > 32) && (c < 128)) formatters[c-32] = f;
}

void vbprintf(buffer d, buffer fmt, vlist *ap)
{
    int state = 0;
    int width = 0;

    foreach_character(i, fmt) {
        if (state == 1)  {
	    if ((i >= 48) && (i <= 57)) {
		width = width * 10 + i - 48;
	    } else {
		if ((i > 32) && (i < 128) && formatters[i - 32]) {
		    /* XXX width ignored; should pass and handle */
		    formatters[i-32](d, fmt, ap);
		} else {
		    char header[] = "[invalid format %";
		    buffer_write(d, header, sizeof(header) - 1);
		    push_character(d, i);
		    push_u8(d, ']');
		}
		state = 0;
            }
        } else {           
            if ((state == 0) && (i == '%')) {
                state = 1;
            } else {
                push_character(d, i);
            }
        }
    }
}

/* XXX the various debug stuff needs to be folded into one log facility...somewhere */
void log_vprintf(char * prefix, char * log_format, vlist *a)
{
    buffer b = allocate_buffer(transient, 64);
    bprintf(b, "[%T] %s: ", now(), prefix);
    struct buffer f;
    f.start = 0;
    f.contents = log_format;
    f.end = runtime_strlen(log_format);
    vbprintf(b, &f, a);
    debug(b);
}

void log_printf(char * prefix, char * log_format, ...)
{
    vlist a;
    vstart(a, log_format);
    log_vprintf(prefix, log_format, &a);
}
