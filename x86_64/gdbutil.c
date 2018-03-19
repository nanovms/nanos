#include <sruntime.h>
#include <gdbutil.h>


u64 parse_int(buffer b, u32 base, u64 *intValue)
{
  int hexValue;
  int result = 0;
  *intValue = 0;

  while (buffer_length(b)) {
    hexValue = digit_of(peek_char(b));
    if (hexValue >= 0) {
      get_char(b);
      result = 1;
      *intValue = (*intValue * base) + hexValue;
    } else break;
  }
  return(result);
}


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

    for (i = 0; i < count; i++) {
        ch = *(char *)(mem++);
        bprintf(b, "%02x", (u32)ch);
    }
    return (true);
}

boolean hex2mem (buffer b, void *mem, int count)
{
    int i;
    unsigned char ch;

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

    while ((ch = get_char(b))) {
        push_character (g->send_buffer, ch);
        checksum += ch;
    }
    
    bprintf (g->send_buffer, "#%02x", checksum);
    gdb_send(g, g->send_buffer);
}


void handle_query(gdb g, buffer b, string out, handler h) 
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
            void (*f)(gdb, buffer, string) = h[i].body;
            buffer_consume(b, j);
            f(g, b, out);
            return;
        }
    }
    // what to say if we dont understand?
}
