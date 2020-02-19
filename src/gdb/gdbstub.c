#include <gdb_internal.h>
#include <kvm_platform.h>

int signalmap[]={8, 5, 0, 5, 16, 16, 4, 8, 7, 11, 11, 11, 11, 11, 11, 0, 7};

int computeSignal (int exceptionVector)
{
    if (exceptionVector > (sizeof(signalmap)/sizeof(int))) 
        return(7);
    return(signalmap[exceptionVector]);
}

static int sigval;

static void reset_parser(gdb g)
{
    g->checksum =0;
    reset_buffer(g->out);
    reset_buffer(g->in);
    reset_buffer(g->output);
    g->sent_checksum = -1;
}

closure_function(1, 1, context, gdb_handle_exception,
                 gdb, g,
                 context, frame)
{
    gdb g = bound(g);
    u64 exceptionVector = frame[FRAME_VECTOR];
    //     rprintf ("gdb exception: %ld %p [%p %p] %p %p\n", exceptionVector, g, frame, thread_frame(g->t), frame[FRAME_RIP], *(u64 *)frame[FRAME_RIP]);
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
    reset_buffer(g->output);
    bprintf (g->output, "T");
    print_number(g->output, (u64)sigval, 16, 2);
    putpacket (g, g->output);
    runloop();
}

static boolean return_offsets(gdb g, buffer in, string out)
{
    return true;
}

static boolean return_supported(gdb g, buffer in, string out)
{
    return true;
}

static boolean current_thread(gdb g, buffer in, string out)
{
    bprintf(out, "0");
    return true;
}

static boolean attached(gdb g, buffer in, string out)
{
    bprintf(out, "1");
    return true;
}



static struct handler query_handler[] = {
    {"Offset", return_offsets},
    {"Supported", return_supported},
    {"C", current_thread}, // return 0
    {"Attached", attached}, // 0 for started anew
    //  {"TStatus", 0}, // say T0
    //  {"Symbol", 0}, //OK
    //  {"J", get_debugger_current_thread},
    //  {"fThreadInfo", start_thread_dump},
    //  {"sThreadInfo", continue_thread_dump},
    //  {"ThreadExtraInfo", extra},
    {0,0}
};

#define TRAP_FLAG 0x100
#define RESUME_FLAG U64_FROM_BIT(16)
static void start_slave(gdb g, boolean stepping)
{
    // a little more symbolic here please
    if (stepping) {
        thread_frame(g->t)[FRAME_FLAGS] |= TRAP_FLAG;
    } else {
        thread_frame(g->t)[FRAME_FLAGS] &= ~TRAP_FLAG;
        thread_frame(g->t)[FRAME_FLAGS] |= RESUME_FLAG;
    }

    rprintf ("slave run %p %p %p %p %d\n", g, g->t, thread_frame(g->t), thread_frame(g->t)[FRAME_RIP], stepping);
    // XXX revisit
    // enqueue(runqueue, g->t->run);
}


static boolean apply_vcont(gdb g, buffer in, buffer out)
{
    u64 trash;

    rprintf ("vcont %b\n", in);
    if (check(in, ';')) {
        char kind = get_char(in);
        switch(kind) {
        case 'S':
            // step with signal?
            parse_int(in, 16, &trash);
        case 's':
            start_slave(g, true);
            // thread may be specific
            /*
              if (check(in,':')){
              u64 t;
              parse_int(in, 16, &t);
              
              } else {
              start_slave(g, false);
              }
            */
            // dont reply
            return false;
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
    }
    return true;
}


boolean return_support_conts(gdb g, buffer in, string out)
{
    bprintf(out, "vCont;c;C;s;S;t;T");
    return true;
}

static struct handler v_handler[] = {
    {"Cont?", return_support_conts},
    {"Cont", apply_vcont},
    {0,0}
};



static boolean handle_request(gdb g, buffer b, buffer output)
{
    u64 addr, length;
    int stepping = 0;

    char command = get_char(b);

    switch (command) {
    case '?':
        bprintf(output, "S");
        print_number(output, (u64)sigval, 16, 2);
        break;
    case 'd':
        //remote_debug = !(remote_debug);	/* toggle debug flag */
        break;
        
    case 'g':		/* return the value of the CPU registers */
        mem2hex (output, thread_frame(g->t), 8*24);
        break;

    case 'G':		/* set the value of the CPU registers - return OK */
        // manifest constant
        hex2mem (b, (char *) thread_frame(g->t), 8*24);
        bprintf (output, "OK");
        break;

    case 'H': /* set thread */
        bprintf (output, "OK");
        break;
        
    case 'q':
        handle_query(g, b, output, query_handler);
        break;
        
    case 'v':
        return handle_query(g, b, output, v_handler);
        break;

    case 'p':
        bprintf(output, "00000000");
        break;

    case 'P':		/* set the value of a single CPU register - return OK */
        {
            u64 regno;
            if (parse_int (b, 16, &regno) && (get_char(b) == '='))                
                if (regno < FRAME_MAX) {
                    hex2mem (b, thread_frame(g->t) + regno, 8);
                    bprintf (output, "OK");
                    break;
                }
            
            bprintf (output, "E01");
            break;
        }
        
        /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
    case 'm':
        if (parse_hex_pair(b, &addr, &length)) {
            if (!mem2hex (output, pointer_from_u64(addr), length)) {
                rprintf ("memory error\n");
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
            thread_frame(g->t)[FRAME_RIP] = addr;
        start_slave(g, stepping);
        break;
        
        /* kill the program */
    case 'k':		
        vm_exit(VM_EXIT_GDB);
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
                    if (breakpoint_insert(addr, 0, 8))
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

    return true;
}

#define ASCII_CONTROL_C 0x03
// not completely reassembling (meaning we dont handle fragments?)
closure_function(1, 1, status, gdbserver_input,
                 gdb, g,
                 buffer, b)
{
    gdb g = bound(g);
    char ch = '0';
    /* wait around for the start character, ignore all other characters */
    while (buffer_length(b) && ((ch = get_char(b)) != '$')) {
        if (ch == ASCII_CONTROL_C) { //wth?
        //        gdb_handle_exception(g, 1, g->registers);
            rprintf ("control-c\n");
            return STATUS_OK;
        }
    }
 retry:
    g->sent_checksum = -1;
  
    /* now, read until a # or end of buffer is found */
    while (buffer_length(b)) {
        ch = get_char(b);
        // xxx - eah - workaround from trace, not the document
        if (ch == '$')
            goto retry;
        if (ch == '#')
            break;
        g->checksum = g->checksum + ch;
        push_character(g->in, ch);
    }

    if (ch == '#') {
        // xxx may be on a segmentation boundary
        ch = get_char(b);
        g->sent_checksum = digit_of(ch) << 4;
        ch = get_char(b);
        g->sent_checksum += digit_of(ch);
    
        if (g->checksum != g->sent_checksum){
            push_character(g->out, '-');	/* failed checksum */
            g->sent_checksum = -1;
            g->checksum =0;
        } else {
            push_character(g->out, '+');	/* successful transfer */
            apply(g->output_handler, g->out);
            if (handle_request(g, g->in, g->output)) {
                putpacket (g, g->output);
            }

        }
        reset_parser(g);            
        return STATUS_OK;
    }
    return STATUS_OK;
}

buffer_handler init_gdb(heap h,
                        process p,
                        buffer_handler outh)
{
    gdb g = allocate(h, sizeof(struct gdb));
    g->output_handler = outh;
    // why do I need three here?
    g->output = allocate_buffer(h, 256); 
    g->send_buffer = allocate_buffer(h, 256); 
    g->out = allocate_buffer(h, 256); 
    g->in = allocate_buffer(h, 256);
    g->h = h;
    g->t = vector_get(p->threads, 0);
    thread_frame(g->t)[FRAME_FAULT_HANDLER] = u64_from_pointer(closure(h, gdb_handle_exception, g));
    reset_parser(g);
    return closure(h, gdbserver_input, g);
}
