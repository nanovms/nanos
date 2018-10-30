#include <gdb_internal.h>

boolean parse_hex_pair(buffer in, u64 *first, u64 *second)
{
    parse_int(in, 16, first);
    check(in, ',');
    parse_int(in, 16, second);
    return(true);
}

/* convert the memory pointed to by mem into hex, placing result in buf */
/* return a pointer to the last char put in buf (null) */
/* If MAY_FAULT is non-zero, then we should set mem_err in response to
   a fault; if zero treat a fault like any other fault in the stub.  */
boolean mem2hex (string b, void *mem, int count)
{
    int i;
    unsigned char ch;
    if (!validate_virtual(mem, count)) {
        rprintf ("validation failed\n");
        return false;
    }
    for (i = 0; i < count; i++) {
        ch = *(unsigned char *)(mem++);
        print_number(b, (u64)ch, 16, 2);
    }
    return (true);
}

boolean hex2mem (buffer b, void *mem, int count)
{
    int i;
    unsigned char ch;

    if (!validate_virtual(mem, count)) 
        return false;
    
    for (i = 0; i < count; i++) {
        ch = digit_of(get_char(b)) << 4;
        ch = ch + digit_of(get_char(b));
        *((u8 *)mem++) = ch;
    }
    return (true);
}

void putpacket(gdb g, string b)
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
    print_number(g->send_buffer, (u64)checksum, 16, 2);
    apply(g->output_handler, g->send_buffer);
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
