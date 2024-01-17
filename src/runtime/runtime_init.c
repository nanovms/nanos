#include <runtime.h>
#include <log.h>

void initialize_buffer();

closure_function(0, 0, void, ignore_body) {}
BSS_RO_AFTER_INIT thunk ignore;
BSS_RO_AFTER_INIT status_handler ignore_status;
BSS_RO_AFTER_INIT value null_value;
static char *hex_digits="0123456789abcdef";

void print_u64(u64 s)
{
    buffer b = little_stack_buffer(16);
    for (int x = 60; x >= 0; x -= 4)
        push_u8(b, hex_digits[(s >> x) & 0xf]);
    buffer_print(b);
}

void print_number(buffer s, u64 x, int base, int pad)
{
    u64 q, r;
    DIV(x, base, q, r);
    if (q > 0 || pad > 1)
        print_number(s, q, base, pad - 1);
    push_u8(s, hex_digits[r]);
}

void print_signed_number(buffer s, s64 x, int base, int pad)
{
    if (x < 0) {
        push_u8(s, '-');
        x = -x;
    }
    print_number(s, x, base, pad);
}

static void format_pointer(buffer dest, struct formatter_state *s, vlist *a)
{
    push_u8(dest, '0');
    push_u8(dest, 'x');
    u64 x = varg(*a, word);
    int pad = sizeof(word) * 2;
    print_number(dest, x, 16, pad);
}

static inline void fill(buffer b, int len, u8 c)
{
    for (int i = 0; i < len; i++) push_u8(b, c);
}

static void format_number(buffer dest, struct formatter_state *s, vlist *a)
{
    int base = s->format == 'x' ? 16 : 10;

    s64 x;
    int sign = 0;
    char buf[64];
    buffer tmp = alloca_wrap_buffer(buf, sizeof(buf));

    buffer_clear(tmp);
    if (s->modifier == 'l')
        x = varg(*a, s64);
    else {
        if (s->format == 'd')
            x = varg(*a, int);
        else
            x = varg(*a, unsigned);
    }
    if (s->format == 'd' && x < 0) {
	/* emit sign & two's complement */
        sign = 1;
        x = -x;
    }
    print_number(tmp, x, base, s->precision);
    int len = buffer_length(tmp) + sign;
    if (s->precision == 0 && x == 0)
        len = 0;
    if (sign && s->fill == '0')
        push_u8(dest, '-');
    if (len < s->width && s->align == 0)
        fill(dest, s->width - len, s->fill);
    if (sign && s->fill != '0')
        push_u8(dest, '-');
    if (!(s->precision == 0 && x == 0))
        push_buffer(dest, tmp);
    if (len < s->width && s->align == '-')
        fill(dest, s->width - len, ' ');
}

static void format_buffer(buffer dest, struct formatter_state *s, vlist *ap)
{
    assert(push_buffer(dest, varg(*ap, buffer)));
}

static void format_character(buffer dest, struct formatter_state *s, vlist *a)
{
    int x = varg(*a, int);
    push_character(dest, x);
}

static void format_sstring(buffer dest, struct formatter_state *s, vlist *a)
{
    sstring ss = varg(*a, sstring);
    int len = ss.len;
    if ((s->precision > 0) && (s->precision < len))
        len = s->precision;
    if (len < s->width && s->align == 0)
        fill(dest, s->width - len, ' ');
    assert(buffer_write(dest, ss.ptr, len));
    if (len < s->width && s->align == '-')
        fill(dest, s->width - len, ' ');
}

static void format_spaces(buffer dest, struct formatter_state *s, vlist *a)
{
    int n = varg(*a, int);
    fill(dest, n, ' ');
}

// maybe the same?
BSS_RO_AFTER_INIT heap transient;

// init linker sets would clean up the platform dependency, if you link
// with it, it gets initialized
void init_runtime(heap general, heap safe)
{
    // environment specific
    transient = safe;
    register_format('p', format_pointer, 0);
    register_format('x', format_number, 1);
    register_format('d', format_number, 1);
    register_format('u', format_number, 1);
    register_format('s', format_sstring, 0);
    register_format('b', format_buffer, 0);
    register_format('n', format_spaces, 0);
    register_format('c', format_character, 0);
    ignore = closure(general, ignore_body);
    ignore_status = (void*)ignore;
    null_value = wrap_buffer(general, "", 1);
}

void rput_sstring(sstring s)
{
    console_write(s.ptr, s.len);
    klog_write(s.ptr, s.len);
}

#define STACK_CHK_GUARD 0x595e9fbd94fda766

RO_AFTER_INIT u64 __attribute__((weak)) __stack_chk_guard = STACK_CHK_GUARD;

void __stack_chk_guard_init()
{
    __stack_chk_guard = random_u64();
}

#ifndef KERNEL
void __attribute__((noreturn)) __stack_chk_fail(void)
{
    halt("stack check failed\n");
}
#endif
