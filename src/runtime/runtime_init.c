#include <runtime.h>

void initialize_buffer();

closure_function(0, 0, void, ignore_body) {}
thunk ignore;
status_handler ignore_status;
value null_value;
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

static void format_pointer(buffer dest, struct formatter_state *s, vlist *a)
{
    push_u8(dest, '0');
    push_u8(dest, 'x');
    u64 x = varg(*a, word);
    int pad = sizeof(word) * 2;
    print_number(dest, x, 16, pad);
}

static void format_number(buffer dest, struct formatter_state *s, vlist *a)
{
    int base = s->format == 'x' ? 16 : 10;

    s64 x;
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
        push_u8(dest, '-');
        x = -x;
    }

    print_number(dest, x, base, s->width);
}

static void format_buffer(buffer dest, struct formatter_state *s, vlist *ap)
{
    push_buffer(dest, varg(*ap, buffer));
}

static void format_character(buffer dest, struct formatter_state *s, vlist *a)
{
    int x = varg(*a, int);
    push_character(dest, x);
}

static void format_cstring(buffer dest, struct formatter_state *s, vlist *a)
{
    char *c = varg(*a, char *);
    if (!c) c = (char *)"(null)";
    int len = runtime_strlen(c);
    buffer_write(dest, c, len);
}

static void format_spaces(buffer dest, struct formatter_state *s, vlist *a)
{
    int n = varg(*a, int);
    for (int i = 0; i < n; i++) push_u8(dest, ' ');
}

// maybe the same?
heap errheap;
heap transient;

// init linker sets would clean up the platform dependency, if you link
// with it, it gets initialized
void init_runtime(heap general, heap safe)
{
    // environment specific
    transient = general;
    register_format('p', format_pointer, 0);
    register_format('x', format_number, 1);
    register_format('d', format_number, 1);
    register_format('s', format_cstring, 0);
    register_format('b', format_buffer, 0);
    register_format('n', format_spaces, 0);
    register_format('c', format_character, 0);
    ignore = closure(general, ignore_body);
    ignore_status = (void*)ignore;
    errheap = safe;
    null_value = wrap_buffer_cstring(general, "");
}

#define STACK_CHK_GUARD 0x595e9fbd94fda766

u64 __stack_chk_guard = STACK_CHK_GUARD;

void __stack_chk_guard_init()
{
    __stack_chk_guard = random_u64();
}

void __attribute__((noreturn)) __stack_chk_fail(void)
{
    halt("stack check failed\n");
}
