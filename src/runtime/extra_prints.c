#ifdef KERNEL
#include <kernel.h>
#include <symtab.h>
#else
#include <runtime.h>
#endif


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

/* just a little tool for debugging */
void print_csum_buffer(buffer s, buffer b)
{
    u64 csum = 0;
    for (int i = 0; i < buffer_length(b); i++)
        csum += *(u8*)buffer_ref(b, i);
    bprintf(s, "%lx", csum);
}

/* This is really lame, but we're pruning value printing in the stage2 build
   to keep the image size under 64kB, else Xen/AWS booting will fall over.

   See: https://github.com/nanovms/nanos/pull/1383
*/

#ifndef BOOT
closure_function(1, 2, boolean, _sort_handler,
                 vector, pairs,
                 value, s, value, v)
{
    assert(is_symbol(s));
    vector_push(bound(pairs), s);
    vector_push(bound(pairs), v);
    return true;
}

static boolean _symptr_compare(void *a, void *b)
{
    symbol s1 = *(symbol*)a;
    symbol s2 = *(symbol*)b;
    return buffer_lt(symbol_string(s2), symbol_string(s1));
}

static void print_value_internal(buffer dest, value v, table *visited, s32 indent, s32 depth);

static void print_tuple_internal(buffer b, tuple t, table *visited, s32 indent, s32 depth)
{
    /* This is a little heavy, but we don't have a sorted iterate. */
    pqueue pq = allocate_pqueue(transient, _symptr_compare);
    assert(pq != INVALID_ADDRESS);
    vector v = allocate_vector(transient, 16);
    assert(v != INVALID_ADDRESS);
    iterate(t, stack_closure(_sort_handler, v));

    for (int i = 0; i < vector_length(v); i += 2) {
        void *p = buffer_ref(v, i * sizeof(void *));
        pqueue_insert(pq, p);
    }

    bprintf(b, "(");
    if (indent >= 0)
        indent++;
    void **p;
    boolean sub = false;
    while ((p = pqueue_pop(pq)) != INVALID_ADDRESS) {
        symbol s = p[0];
        value v = p[1];
        if (sub) {
            if (indent >= 0)
                bprintf(b, "\n%n", indent);
            else
                bprintf(b, " ");
        } else {
            sub = true;
        }
        bytes start = buffer_length(b);
        bprintf(b, "%b:", symbol_string(s));
        s32 next_indent = indent >= 0 ? indent + buffer_length(b) - start : indent;
        print_value_internal(b, v, visited, next_indent, depth);
    }
    bprintf(b, ")");
    deallocate_vector(v);
    deallocate_pqueue(pq);
}

closure_function(6, 2, boolean, print_vector_each,
                 buffer, b, vector, vec, table *, visited, s32, indent, s32, depth, boolean *, sub,
                 value, a, value, v)
{
    buffer b = bound(b);
    if (*bound(sub)) {
        if (bound(indent) >= 0)
            bprintf(b, "\n%n", bound(indent));
        else
            bprintf(b, " ");
    } else {
        *bound(sub) = true;
    }
    print_value_internal(b, v, bound(visited), bound(indent), bound(depth));
    return true;
}

static void print_vector_internal(buffer b, vector v, table *visited, s32 indent, s32 depth)
{
    bprintf(b, "[");
    boolean sub = false;
    iterate(v, stack_closure(print_vector_each, b, v, visited, indent < 0 ? indent : indent + 1, depth, &sub));
    bprintf(b, "]");
}

/* Ideally, we would have types distinguishing text-only and binary buffers,
   facilitating UTF8 handling. For now, squelch output on non-printable ASCII. */

static boolean is_binary_buffer(buffer b)
{
    foreach_character(i, c, b) {
        if (c < 0x20 || c > 0x7e)
            return true;
    }
    return false;
}

static void print_value_internal(buffer dest, value v, table *visited, s32 indent, s32 depth)
{
    if (is_composite(v)) {
        if (!*visited) {
            *visited = allocate_table(transient, identity_key, pointer_equal);
            assert(visited != INVALID_ADDRESS);
        }

        if (table_find(*visited, v)) {
            bprintf(dest, "<visited>");
        } else {
            table_set(*visited, v, (void *)1);
            value wrapped = get_tuple(v, sym(/wrapped));
            if (wrapped)
                table_set(*visited, wrapped, (void *)1);
            if (depth > 0) {
                if (is_tuple(v))
                    print_tuple_internal(dest, v, visited, indent, depth - 1);
                else
                    print_vector_internal(dest, v, visited, indent, depth - 1);
            } else {
                bprintf(dest, "<pruned>");
            }
        }
    } else if (is_symbol(v)) {
        bprintf(dest, "%b", symbol_string((symbol)v));
    } else if (v == null_value) {
        bprintf(dest, "<null>");
    } else if (is_integer(v)) {
        if (is_signed_integer_value(v)) {
            s64 x;
            assert(s64_from_value(v, &x));
            bprintf(dest, "%ld", x);
        } else {
            u64 x;
            assert(u64_from_value(v, &x));
            bprintf(dest, "%lu", x);
        }
    } else if (is_string(v)) {
        bprintf(dest, "%b", v);
    } else {
        buffer b = (buffer)v;
        if (is_binary_buffer(b))
            bprintf(dest, "{binary, length %d}", buffer_length(b));
        else
            bprintf(dest, "%b", b);
    }
}

void print_value(buffer dest, value v, tuple attrs)
{
    u64 indent = (s32)-1;
    u64 depth = 0;

    if (attrs) {
        get_u64(attrs, sym(indent), &indent);
        get_u64(attrs, sym(depth), &depth);
    }

    table visited = 0;
    print_value_internal(dest, v, &visited, indent, depth == 0 ? S32_MAX : depth);
    if (visited)
        deallocate_table(visited);
}

static void format_value(buffer dest, struct formatter_state *s, vlist *v)
{
    value x = varg(*v, value);
    if (!x) {
        bprintf(dest, "(none)");
        return;
    }

    print_value(dest, x, 0);
}

static void format_value_with_attributes(buffer dest, struct formatter_state *s, vlist *v)
{
    value x = varg(*v, value);
    if (!x) {
        bprintf(dest, "(none)");
        return;
    }

    value a = varg(*v, tuple);
    assert(!a || is_tuple(a));
    print_value(dest, x, a);
}
#endif

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

static void print_decimal(string b, timestamp t, int prec)
{
    u32 s= t>>32;
    u64 f= t&MASK(32);

    bprintf(b, "%d", s);
    if (f) {
        int count=0;

        bprintf(b,".");

        /* should round or something */
        while ((f *= 10) && (count++ < prec)) {
            u32 d = (f>>32);
            bprintf (b, "%d", d);
            f -= ((u64)d)<<32;
        }
    }
}

static void format_timestamp(buffer dest, struct formatter_state *s, vlist *a)
{
    timestamp t = varg(*a, timestamp);
    print_decimal(dest, t, 6);
}

static void print_fixed(string b, s64 fx)
{
    s64 t = fx;
    if (t < 0) {
        bprintf(b, "-");
        t = -t;
    }
    print_decimal(b, (u64)t, 9);
}

static void format_fixed(buffer dest, struct formatter_state *s, vlist *a)
{
    s64 t = varg(*a, s64);
    print_fixed(dest, t);
}

static void format_range(buffer dest, struct formatter_state *s, vlist *a)
{
    range r = varg(*a, range);
    bprintf(dest, "[0x%lx 0x%lx)", r.start, r.end);
}

static void format_closure(buffer dest, struct formatter_state *s, vlist *a)
{
    // xxx - we can probably do better here?
    u64 *k = varg(*a, u64 *);
#ifdef KERNEL
    sstring name = find_elf_sym(*k, 0, 0);
    if (!sstring_is_null(name)) {
        bprintf(dest, "%s", name);
        return;
    }
#endif
    bprintf(dest, "%p", *k);
}

void init_extra_prints(void)
{
#ifndef BOOT
    register_format('v', format_value, 0);
    register_format('V', format_value_with_attributes, 0);
#endif
    register_format('X', format_hex_buffer, 0);
    register_format('T', format_timestamp, 0);
    register_format('R', format_range, 0);
    register_format('C', format_csum_buffer, 0);
    register_format('F', format_closure, 0);
    register_format('f', format_fixed, 0);
}
