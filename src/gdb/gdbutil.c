#include <gdb_internal.h>

boolean parse_hex_pair(buffer in, u64 *first, u64 *second)
{
    parse_int(in, 16, first);
    check(in, ',');
    parse_int(in, 16, second);
    return(true);
}

/* encode count bytes of mem in hex */
boolean mem2hex (string b, void *mem, int count)
{
    int i;
    unsigned char ch;
    if (!validate_virtual(mem, count))
        return false;
    for (i = 0; i < count; i++) {
        ch = *(unsigned char *)(mem++);
        print_number(b, (u64)ch, 16, 2, false);
    }
    return (true);
}

/* write count bytes from hex buffer into mem */
boolean hex2mem (buffer b, void *mem, int count)
{
    int i;
    unsigned char ch;

    if (!validate_virtual_writable(mem, count))
        return false;
    
    for (i = 0; i < count; i++) {
        ch = digit_of(get_char(b)) << 4;
        ch = ch + digit_of(get_char(b));
        *((u8 *)mem++) = ch;
    }
    return (true);
}

closure_function(1, 0, void, gdb_deferred_tx,
                 gdb, g)
{
    gdb g = bound(g);
    u64 flags = spin_lock_irq(&g->send_lock);
    apply(g->output_handler, g->send_buffer);
    g->sending = false;
    spin_unlock_irq(&g->send_lock, flags);
    closure_finish();
}

static void put_sendstring(gdb g, string b)
{
    unsigned char checksum;
    char ch;

    reset_buffer(g->send_buffer);
    /*  $<packet info>#<checksum>. */

    push_character(g->send_buffer, '$');
    checksum = 0;

    // if push_character was abstracted, this could happen without the copy
    while ((ch = get_char(b))) {
        push_character (g->send_buffer, ch);
        checksum += ch;
    }

    bprintf (g->send_buffer, "#");
    print_number(g->send_buffer, (u64)checksum, 16, 2, false);
}

void putpacket_deferred(gdb g, string b)
{
    u64 flags = spin_lock_irq(&g->send_lock);
    if (g->sending) {
        spin_unlock_irq(&g->send_lock, flags);
        rprintf("putpacket_deferred dropped, already sending\n");
        return;
    }
    g->sending = true;
    put_sendstring(g, b);
    async_apply_bh(closure(g->h, gdb_deferred_tx, g));
    spin_unlock_irq(&g->send_lock, flags);
}

void putpacket(gdb g, string b)
{
    u64 flags = spin_lock_irq(&g->send_lock);
    if (g->sending) {
        spin_unlock_irq(&g->send_lock, flags);
        rprintf("putpacket dropped, already sending\n");
        return;
    }
    put_sendstring(g, b);
    apply(g->output_handler, g->send_buffer);
    spin_unlock_irq(&g->send_lock, flags);
}


boolean handle_query(gdb g, buffer b, string out, handler h) 
{
    int i;

    for (i = 0 ; h[i].name; i++) {
        int j;
        char *n = h[i].name;
        char *m = buffer_ref(b, 0);

        for (j = 0; 
             n[j] && (j < buffer_length(b)) && (n[j] == m[j]);
             j++);

        if (!(n[j])) {
            buffer_consume(b, j);
            return h[i].body(g, b, out);
        }
    }
    // means send empty
    return true;
}
