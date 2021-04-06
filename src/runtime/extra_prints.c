#include <runtime.h>


static char *hex_digit="0123456789abcdef";
void print_byte(buffer s, u8 f)
{
    push_u8(s, hex_digit[f >> 4]);
    push_u8(s, hex_digit[f & 15]);
}

void print_hex_buffer(buffer s, buffer b)
{
    int len = buffer_length(b);
    int wlen = 4;
    int rowlen = wlen * 4;
    boolean first = true;

    for (int i = 0 ; i<len ; i+= 1) {
        if (!(i % rowlen)) {
            if (!first) push_u8(s, '\n');
            first = false;
            print_byte(s, i>>24);
            print_byte(s, i>>16);
            print_byte(s, i>>8);
            print_byte(s, i);
            push_u8(s, ':');
        }
        if (!(i % wlen)) push_u8 (s, ' ');
        print_byte(s, *(u8 *)buffer_ref(b, i));
        push_u8(s, ' ');
    }
    // better handling of empty buffer
    push_u8(s, '\n');
}

void print_uuid(buffer b, u8 *uuid)
{
    /* UUID format: 00112233-4455-6677-8899-aabbccddeeff */
    for (int i = 0; i < 4; i++)
        bprintf(b, "%02x", uuid[i]);
    bprintf(b, "-%02x%02x-%02x%02x-%02x%02x-", uuid[4], uuid[5], uuid[6],
            uuid[7], uuid[8], uuid[9]);
    for (int i = 10; i < 16; i++)
        bprintf(b, "%02x", uuid[i]);
}
KLIB_EXPORT(print_uuid);

/* just a little tool for debugging */
void print_csum_buffer(buffer s, buffer b)
{
    u64 csum = 0;
    for (int i = 0; i < buffer_length(b); i++)
        csum += *(u8*)buffer_ref(b, i);
    bprintf(s, "%lx", csum);
}

static void print_tuple_internal(buffer b, tuple t, table visited, u32 depth);

closure_function(4, 2, boolean, _value_handler,
                 buffer, b, boolean *, sub, table, visited, u32, depth,
                 symbol, a, value, v)
{
    if (*bound(sub))
        push_character(bound(b), ' ');
    bprintf(bound(b), "%b:", symbol_string((symbol)a));

    /* this should be "print_value" */
    if (is_tuple(v)) {
        if (table_find(bound(visited), v)) {
            bprintf(bound(b), "<visited>");
        } else {
            table_set(bound(visited), v, (void *)1);
            if (bound(depth) > 1)
                print_tuple_internal(bound(b), v, bound(visited), bound(depth) - 1);
            else
                bprintf(bound(b), "<pruned>");
        }
    } else {
        bprintf(bound(b), "%b", v);
    }
    *bound(sub) = true;
    return true;
}

static void print_tuple_internal(buffer b, tuple t, table visited, u32 depth)
{
    boolean sub = false;
    bprintf(b, "(");
    iterate(t, stack_closure(_value_handler, b, &sub, visited, depth));
    bprintf(b, ")");
}

void print_tuple(buffer b, tuple t, u32 depth)
{
    // XXX need an alloca heap
    table visited = allocate_table(transient, identity_key, pointer_equal);
    assert(visited != INVALID_ADDRESS);
    print_tuple_internal(b, t, visited, depth == 0 ? U32_MAX : depth);
    deallocate_table(visited);
}

static void format_tuple(buffer dest, struct formatter_state *s, vlist *v)
{
    tuple t = varg(*v, tuple);
    if (!t) {
        bprintf(dest, "(none)");
        return;
    }
    print_tuple(dest, t, U32_MAX);
}

void print_value(buffer dest, value v, u32 depth)
{
    if (is_tuple(v))
        print_tuple(dest, (tuple)v, depth);
    else if (is_symbol(v))
        bprintf(dest, "%b", symbol_string((symbol)v));
    else {
        // XXX string vs binary
        buffer b = (buffer)v;
        if (buffer_length(b) > 20)
            bprintf(dest, "{buffer %d}", buffer_length(b));
        else
            bprintf(dest, "%b", b);
    }
}

static void format_value(buffer dest, struct formatter_state *s, vlist *v)
{
    value x = varg(*v, value);
    if (!x) {
        bprintf(dest, "(none)");
        return;
    }

    print_value(dest, x, U32_MAX);
}

static void format_value_with_depth(buffer dest, struct formatter_state *s, vlist *v)
{
    value x = varg(*v, value);
    if (!x) {
        bprintf(dest, "(none)");
        return;
    }

    u32 depth = varg(*v, u32);
    if (depth == 0)
        return; /* meaning? */

    print_value(dest, x, depth);
}

static void format_hex_buffer(buffer dest, struct formatter_state *s, vlist *a)
{
    buffer b = varg(*a, buffer);
    print_hex_buffer(dest, b);
}

static void format_csum_buffer(buffer dest, struct formatter_state *s, vlist *a)
{
    buffer b = varg(*a, buffer);
    print_csum_buffer(dest, b);
}

static void format_timestamp(buffer dest, struct formatter_state *s, vlist *a)
{
    timestamp t = varg(*a, timestamp);
    print_timestamp(dest, t);
}

static void format_range(buffer dest, struct formatter_state *s, vlist *a)
{
    range r = varg(*a, range);
    bprintf(dest, "[0x%lx 0x%lx)", r.start, r.end);
}

static void format_closure(buffer dest, struct formatter_state *s, vlist *a)
{
    // xxx - we can probably do better here?
    void **k = varg(*a, void **);
    struct _closure_common *c = k[1];
    bprintf(dest, "%s", &c->name);
}

void init_extra_prints(void)
{
    register_format('t', format_tuple, 0);
    register_format('v', format_value, 0);
    register_format('V', format_value_with_depth, 0);
    register_format('X', format_hex_buffer, 0);
    register_format('T', format_timestamp, 0);
    register_format('R', format_range, 0);
    register_format('C', format_csum_buffer, 0);
    register_format('F', format_closure, 0);
}
