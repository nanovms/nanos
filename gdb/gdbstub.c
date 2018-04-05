#include <gdb_internal.h>

int signalmap[]={8, 5, 0, 5, 16, 16, 4, 8, 7, 11, 11, 11, 11, 11, 11, 0, 7};

int computeSignal (int exceptionVector)
{
    if (exceptionVector > (sizeof(signalmap)/sizeof(int))) 
        return(7);
    return(signalmap[exceptionVector]);
}

static int sigval;

CLOSURE_1_1(gdb_handle_exception, void, gdb, context);

void gdb_handle_exception (gdb g, context frame)
{
    int exceptionVector = frame[FRAME_VECTOR];
    
    sigval = computeSignal(exceptionVector);
    reset_buffer(g->output);
    /*
      byte swap
      bprintf (output, "T%02x%x:%08x;%x:%08x;%x:%08x;",
      sigval,
      ESP, c->esp,
      EBP, c->ebp,
      PC, c->eip);
    */
    bprintf (g->output, "T%02x", sigval);
    putpacket (g, g->output);
}

static void return_offsets(gdb g, buffer in, string out)
{
    putpacket(g, out);
}

static void return_supported(gdb g, buffer in, string out)
{
    // we do this at the end, neh?
    //    putpacket(g, out);
}

static void current_thread(gdb g, buffer in, string out)
{
    bprintf(out, "0");
    putpacket(g, g->out);
}


static struct handler query_handler[] = {
    {"Offset", return_offsets},
    {"Supported", return_supported},
    {"C", current_thread}, // return 0
    {"Attached", current_thread}, // 0 for started anew
    //  {"TStatus", 0}, // say T0
    //  {"Symbol", 0}, //OK
    //  {"J", get_debugger_current_thread},
    //  {"fThreadInfo", start_thread_dump},
    //  {"sThreadInfo", continue_thread_dump},
    //  {"ThreadExtraInfo", extra},
    {0,0}
};

static void start_slave(gdb g, boolean stepping)
{
    if (stepping) {
        g->registers[FRAME_FLAGS] |= 0x100;
    } else {
        g->registers[FRAME_FLAGS] &= 0xfffffeff;
        // resume flag
        g->registers[FRAME_FLAGS] |= (1<<16);
    }
    // trap_frame = r;
    // run thread
}


static void apply_vcont(gdb g, buffer in, buffer out)
{
    u64 trash;

    if (check(in, ';')) {
        char kind = get_char(in);
        switch(kind) {
        case 'S':
            // step with signal?
            parse_int(in, 16, &trash);
        case 's':
            if (check(in,':')){
                u64 t;
                parse_int(in, 16, &t);
                start_slave(g, true);
            } else {
                start_slave(g, false);
            }
            break;

            break;
        case 't':
            break;
        case 'T':
            break;
        case 'C':{
            u64 sig;
            parse_int(in, 16, &sig);
            // what am i supposed to do with sig?
            start_slave(g, false);
        }
        case 'c':
            if (check(in,':')) {
                u64 t;
                parse_int(in, 16, &t);
                start_slave(g, false);
            } else {
                start_slave(g, false);
            }
        }
        apply_vcont(g, in, out);
    }
}


void return_support_conts(gdb g, buffer in, string out)
{
    bprintf(out, "vCont;c;C;s;S;t;T");
    putpacket (g, out);
}

static struct handler v_handler[] = {
    {"Cont?", return_support_conts},
    {"Cont", apply_vcont},
    {0,0}
};



static void handle_request(gdb g, buffer b)
{
    u64 addr, length;
    int stepping = 0;
    buffer output = g->output;

    reset_buffer(output);

    char command = get_char(b);

    switch (command) {
    case '?':
        bprintf(output, "S%02x", sigval);
        break;
    case 'd':
        //remote_debug = !(remote_debug);	/* toggle debug flag */
        break;
    case 'g':		/* return the value of the CPU registers */
        mem2hex (output, g->registers, sizeof(context));
        break;

    case 'G':		/* set the value of the CPU registers - return OK */
        hex2mem (b, (char *) g->registers, sizeof(context));
        bprintf (output, "OK");
        break;

    case 'H': /* set thread */
        bprintf (output, "OK");
        break;
        
    case 'q':
        handle_query(g, b, output, query_handler);
        break;
        
    case 'v':
        handle_query(g, b, output, v_handler);
        return;

    case 'p':
        bprintf(output, "00000000");
        break;

    case 'P':		/* set the value of a single CPU register - return OK */
        {
            u64 regno;
            if (parse_int (b, 16, &regno) && (get_char(b) == '='))                
                if (regno >= 0 && regno < (sizeof(context)/sizeof(u64))) {
                    hex2mem (b, g->registers + regno, 8);
                    bprintf (output, "OK");
                    break;
                }
            
            bprintf (output, "E01");
            break;
        }
        
        /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
    case 'm':
        if (parse_hex_pair(b, &addr, &length)) {
            if (!mem2hex (output, (char *) addr, length)) {
                bprintf(output, "E03");
            }
            break;
        }
        bprintf(output, "E01");
        break;
        
        /* MAA..AA,LLLL: Write LLLL bytes at address AA.AA return OK */
    case 'M':
        /* TRY TO READ '%x,%x:'.  IF SUCCEED, SET PTR = 0 */
        if (parse_hex_pair(b, &addr, &length))
            if (get_char(b) == ':') {
                if (!hex2mem (b, (char *) addr, length)) {
                    bprintf(output, "E03");
                } else {
                    bprintf(output, "OK");
                    break;
                }
            }
        bprintf(output, "E02");
        break;

        /* cAA..AA    Continue at address AA..AA(optional) */
        /* sAA..AA   Step one instruction from AA..AA(optional) */
    case 's':
        stepping = 1;
    case 'c':
        /* try to read optional parameter, pc unchanged if no parm */
        if (parse_int (b, 16, &addr))
            g->registers[FRAME_RIP] = addr;
        start_slave(g, stepping);
        break;
        
        /* kill the program */
    case 'k':		
        QEMU_HALT();
        break;
        
    case 'z':
        {
            char type = get_char(b);
            check(b, ',');
            parse_hex_pair(b, &addr, &length);
            
            switch(type) {
            case '0': 
                {
                    if (breakpoint_remove(addr))
                        bprintf(output, "OK");
                    else
                        bprintf(output, "E08");
                }
            }
            break;
        }

        
    case 'Z':
        {
            char type = get_char(b);
            check(b, ',');
            parse_hex_pair(b, &addr, &length);
            switch(type) {
            case '0': 
                {
                    if (breakpoint_insert(addr))
                        bprintf(output, "OK");
                    else
                        bprintf(output, "E08");
                }
            }
            break;
        }
            
            
    default:
        bprintf(output, "E06");
    }			/* switch */

    /* reply to the request */
    putpacket (g, output);
}

#define ASCII_CONTROL_C 0x03
static CLOSURE_1_1(gdbserver_input, void, gdb, buffer);
static void gdbserver_input(gdb g, buffer b)
{
    unsigned char checksum;
    unsigned char xmitcsum;
    char ch = 0;

    reset_buffer(g->out);
    reset_buffer(g->in);
    
    rprintf ("gdb input %b\n", b);

    /* wait around for the start character, ignore all other characters */
    while (buffer_length(b) && ((ch = get_char(b)) != '$')) {
        if (ch == ASCII_CONTROL_C) { //wth?
        //        gdb_handle_exception(g, 1, g->registers);
            rprintf ("control-c\n");
            return;
        }
    }
 retry:
    checksum = 0;
    xmitcsum = -1;
  
    /* now, read until a # or end of buffer is found */
    while (buffer_length(b)) {
        ch = get_char(b);
        // xxx - eah - workaround from trace, not the document
        if (ch == '$')
            goto retry;
        if (ch == '#')
            break;
        checksum = checksum + ch;
        push_character(g->in, ch);
    }

    if (ch == '#') {
        ch = get_char(b);
        xmitcsum = digit_of(ch) << 4;
        ch = get_char(b);
        xmitcsum += digit_of(ch);
    
        if (checksum != xmitcsum){
            push_character(g->out, '-');	/* failed checksum */
        } else {
            push_character(g->out, '+');	/* successful transfer */
        }
        apply(g->output_handler, g->out);        
        handle_request(g, g->in);
        return;
    }
}

buffer_handler init_gdb(heap h,
                        process p,
                        buffer_handler outh)
{
    gdb g = allocate(h, sizeof(struct gdb));
    g->output_handler = outh;
    g->output = allocate_buffer(h, 256); 
    g->send_buffer = allocate_buffer(h, 256); 
    g->out = allocate_buffer(h, 256); 
    g->in = allocate_buffer(h, 256);
    g->h = h;
    p->handler = closure(h, gdb_handle_exception, g);
    return closure(h, gdbserver_input, g);
}
