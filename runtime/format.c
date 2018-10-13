#include <runtime.h>

static formatter formatters[96]={0};

void register_format(character c, formatter f)
{
    if ((c > 32) && (c < 128)) formatters[c-32] = f;
}

void vbprintf(buffer d, buffer fmt, vlist *ap)
{
    character i;
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
