#include <gdb_internal.h>
#include <gdb_machine.h>

//#define GDB_DEBUG
#ifdef GDB_DEBUG
#define gdb_debug(x, ...) do {tprintf(sym(gdb), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define gdb_debug(...)
#endif

static int sigval;

static inline void clear_thread_stepping(thread t)
{
    frame_disable_stepping(thread_frame(t));
}

static inline void set_thread_stepping(thread t)
{
    frame_enable_stepping(thread_frame(t));
}

static void reset_parser(gdb g)
{
    g->checksum =0;
    reset_buffer(g->out);
    reset_buffer(g->in);
    reset_buffer(g->output);
    g->sent_checksum = -1;
}

static boolean read_thread_id(buffer b, int *tid)
{
    s64 id;
    if (peek_char(b) == 'p') {
        pop_u8(b);
        if (!parse_signed_int(b, 16, &id))
            return false;
        if (peek_char(b) != '.')
            return false;
        pop_u8(b);
    }
    if (!parse_signed_int(b, 16, &id))
        return false;
    *tid = (int)id;
    return true;
}

closure_function(1, 1, context, gdb_handle_exception,
                 gdb, g,
                 context ctx)
{
    gdb g = bound(g);
    g->t = current;
    assert(g->t);
    sigval = computeSignal(ctx->frame);
    if (sigval == 0) {
        fault_handler fh = pointer_from_u64(g->fault_handler);
        return apply(fh, ctx);
    }
    g->p->trap = true;
    wakeup_or_interrupt_cpu_all();
    gdb_debug("gdb exception: %ld %p [%p %p]\n", sigval, g, ctx->frame, g->t->context.frame);
    string output = little_stack_buffer(32);
    reset_buffer(output);
    bprintf (output, "T");
    print_number(output, (u64)sigval, 16, 2);
    bprintf(output, "thread:p1.%x;", g->t->tid);
    putpacket_deferred (g, output);
    runloop();
}

static boolean return_offsets(gdb g, buffer in, string out)
{
    return true;
}

static boolean return_supported(gdb g, buffer in, string out)
{
    if (buffer_strstr(in, ss("multiprocess+"))) {
        g->multiprocess = true;
        bprintf(out, "multiprocess+");
    }
    return true;
}

static boolean current_thread(gdb g, buffer in, string out)
{
    bprintf(out, "QCp1.%x", g->t->tid);
    return true;
}

static boolean attached(gdb g, buffer in, string out)
{
    bprintf(out, "1");
    return true;
}

closure_function(1, 1, boolean, dump_threads,
                 string, out,
                 rbnode n)
{
    thread th = struct_from_field(n, thread, n);
    bprintf(bound(out), "p1.%x,", th->tid);
    return true;
}

static boolean start_thread_dump(gdb g, buffer in, string out)
{
    process p = g->p;
    bprintf(out, "m");
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(dump_threads, out));
    spin_unlock(&p->threads_lock);
    out->end--;
    return true;
}

static boolean continue_thread_dump(gdb g, buffer in, string out)
{
    bprintf(out, "l");
    return true;
}

static boolean extra_info(gdb g, buffer in, string out)
{
    thread t;
    int tid;

    if (peek_char(in) != ',') {
        bprintf(out, "E01");
        return true;
    }
    pop_u8(in);
    if (!read_thread_id(in, &tid)) {
        bprintf(out, "E02");
        return true;
    }
    if ((t = thread_from_tid(g->p, tid)) == INVALID_ADDRESS) {
        bprintf(out, "E03");
        return true;
    }
    // XXX is there a better way to communicate status?
    sstring status;
    if (t->syscall && t->syscall->uc.blocked_on)
        status = ss("Blocked");
    else
        status = ss("Runnable");
    mem2hex(out, status.ptr, status.len);
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
    {"fThreadInfo", start_thread_dump},
    {"sThreadInfo", continue_thread_dump},
    {"ThreadExtraInfo", extra_info},
    {0,0}
};

closure_func_basic(rbnode_handler, boolean, reset_stepping,
                   rbnode n)
{
    thread t = struct_from_field(n, thread, n);
    clear_thread_stepping(t);
    return true;
}

closure_func_basic(rbnode_handler, boolean, sched_thread,
                   rbnode n)
{
    /* XXX this assumes the thread isn't currently running or already scheduled
       and is kind of racey with unblocking */
    thread t = struct_from_field(n, thread, n);
    if (!t->syscall)
        schedule_thread(t);
    return true;
}

static void start_slave(gdb g, boolean stepping, thread t)
{
    if (t == INVALID_ADDRESS) {
        t = thread_from_tid(g->p, g->ctid);
        if (t == INVALID_ADDRESS)
            t = g->t;
    }

    gdb_debug("slave run %p %p %p %d\n", g, t, t->context.frame, stepping);
    g->p->trap = false;
    spin_lock(&g->p->threads_lock);
    rbtree_traverse(g->p->threads, RB_INORDER, stack_closure_func(rbnode_handler, reset_stepping));
    if (stepping)
        set_thread_stepping(t);
    rbtree_traverse(g->p->threads, RB_INORDER, stack_closure_func(rbnode_handler, sched_thread));
    spin_unlock(&g->p->threads_lock);
}


static boolean apply_vcont(gdb g, buffer in, buffer out)
{
    u64 trash;
    thread t = INVALID_ADDRESS;

    gdb_debug("vcont %b\n", in);
    // XXX using only first thread arg
    if (check(in, ';')) {
        char kind = get_char(in);
        switch(kind) {
        case 'S':
            // step with signal?
            parse_int(in, 16, &trash);
        case 's':
            if (check(in, ':')) {
                int tid;
                if (!read_thread_id(in, &tid)) {
                    bprintf(out, "E01");
                    return true;
                }
                t = thread_from_tid(g->p, tid);
            }
            start_slave(g, true, t);
            break;
        case 't':
            break;
        case 'T':
            break;
        case 'C':{
            u64 sig;
            parse_int(in, 16, &sig);
            // what am i supposed to do with sig?
            start_slave(g, false, t);
            break;
        }
        case 'c':
            if (check(in, ':')) {
                int tid;
                if (!read_thread_id(in, &tid)) {
                    bprintf(out, "E01");
                    return true;
                }
                t = thread_from_tid(g->p, tid);
                // XXX ignore other thread specifications, assume they will continue
            }
            start_slave(g, false, t);
            break;
        }
    }
    return false;
}

static boolean apply_kill(gdb g, buffer in, buffer out)
{
    vm_exit(VM_EXIT_GDB);
    return false;
}

boolean return_support_conts(gdb g, buffer in, string out)
{
    bprintf(out, "vCont;c;C;s;S;t;T");
    return true;
}

static struct handler v_handler[] = {
    {"Cont?", return_support_conts},
    {"Cont", apply_vcont},
    {"Kill", apply_kill},
    {0,0}
};

closure_function(1, 0, void, send_ok,
                gdb, g)
{
    gdb g = bound(g);
    bprintf(g->output, "OK");
    putpacket(g, g->output);
    closure_finish();
}

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
        break;
    case 'D':
        bprintf(output, "OK");
        start_slave(g, false, INVALID_ADDRESS);
        break;
    case 'g':		/* return the value of the CPU registers */
        read_registers(output, g->t);
        break;

    case 'G':		/* set the value of the CPU registers - return OK */
        // manifest constant
        write_registers(b, g->t);
        bprintf (output, "OK");
        break;

    case 'H': /* set thread */ {
        int tid;
        char cmd = get_char(b);
        if (cmd < 0) {
            bprintf(output, "E01");
            break;
        }
        if (!read_thread_id(b, &tid)) {
            bprintf(output, "E01");
            break;
        }
        thread t = thread_from_tid(g->p, tid);
        if (t == INVALID_ADDRESS && tid > 0) {
            bprintf(output, "E01");
            break;
        }
        if (cmd == 'g' && tid > 0) {
            g->t = t;
        } else if (cmd == 'c')
            g->ctid = tid;
        bprintf (output, "OK");
        break;
    }
    case 'q':
        handle_query(g, b, output, query_handler);
        break;

    case 'v':
        return handle_query(g, b, output, v_handler);

    case 'p': {
        u64 regno;
        u8 buf[64];  // 512-bit maximum register size
        if (parse_int(b, 16, &regno)) {
            int cnt = get_register(regno, buf, g->t->context.frame);
            if (cnt > 0) {
                mem2hex(output, buf, cnt);
                break;
            }
        }
        bprintf (output, "E01");
        break;
    }
    case 'P':		/* set the value of a single CPU register - return OK */
        {
            u64 regno, val;
            if (parse_int (b, 16, &regno) && (get_char(b) == '=')) {
                // XXX this currently assumes 64-bit registers always
                hex2mem(b, &val, sizeof(val));
                if (set_thread_register(g->t, regno, val))
                    break;
            }
            bprintf (output, "E01");
            break;
        }

        /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
    case 'm':
        if (parse_hex_pair(b, &addr, &length)) {
            if (!mem2hex (output, pointer_from_u64(addr), length)) {
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
                set_write_protect(false);
                if (!hex2mem (b, (char *) addr, length)) {
                    bprintf(output, "E03");
                } else {
                    bprintf(output, "OK");
                }
                set_write_protect(true);
                break;
            }
        bprintf(output, "E02");
        break;
    case 'X':
        if (parse_hex_pair(b, &addr, &length)) {
            if (get_char(b) == ':' && buffer_length(b) >= length) {
                if (length > 0) {
                    if (validate_virtual_writable(pointer_from_u64(addr), length)) {
                        set_write_protect(false);
                        runtime_memcpy((char *)addr, buffer_ref(b, 0), length);
                        set_write_protect(true);
                    } else {
                        bprintf(output, "E03");
                    }
                }
                bprintf(output, "OK");
                break;
            }
        }
        bprintf(output, "E02");
        break;
    case 'T':  {
        int tid;
        if (read_thread_id(b, &tid) && thread_from_tid(g->p, tid) != INVALID_ADDRESS) {
             bprintf(output, "OK");
            break;
        } else
            bprintf(output, "E01");
        break;
    }
        /* cAA..AA    Continue at address AA..AA(optional) */
        /* sAA..AA   Step one instruction from AA..AA(optional) */
    case 's':
        stepping = 1;
    case 'c':
        /* try to read optional parameter, pc unchanged if no parm */
        if (parse_int (b, 16, &addr))
            set_thread_pc(g->t, addr);
        start_slave(g, stepping, INVALID_ADDRESS);
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
            case '1':
                {
                    if (breakpoint_remove(g->h, addr, closure(g->h, send_ok, g)))
                        return false;
                    else {
                        rprintf("hardware breakpoint could not be found\n");
                        bprintf(output, "E08");
                    }
                }
            }
            break;
        }


    case 'Z':
        {
            char type = get_char(b);
            check(b, ',');
            parse_hex_pair(b, &addr, &length);
            if (addr >= USER_LIMIT) {
                rprintf("kernel breakpoints not currently allowed\n");
                bprintf(output, "E08");
                break;
            }
            switch(type) {
            case '1':
                {
                    if (breakpoint_insert(g->h, addr, 0, 8, closure(g->h, send_ok, g)))
                        return false;
                    else {
                        rprintf("maximum number of hardware breakpoints reached\n");
                        bprintf(output, "E08");
                    }
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
                 buffer b)
{
    gdb g = bound(g);
    char ch = '0';
    /* wait around for the start character, ignore all other characters */
    while (buffer_length(b) && ((ch = get_char(b)) != '$')) {
        if (ch == ASCII_CONTROL_C) {
            g->p->trap = true;
            wakeup_or_interrupt_cpu_all();
            gdb_debug("gdb: control-c\n");
            reset_buffer(g->output);
            bprintf(g->output, "T02");
            putpacket(g, g->output);
            return STATUS_OK;
        }
    }
 retry:
    g->sent_checksum = -1;

    boolean esc = false;
    /* now, read until a # or end of buffer is found */
    while (buffer_length(b)) {
        ch = get_char(b);
        // xxx - eah - workaround from trace, not the document
        if (ch == '$')
            goto retry;
        if (ch == '#')
            break;
        g->checksum = g->checksum + ch;
        /* handle binary data */
        if (esc) {
            ch ^= 0x20;
            esc = false;
        } else if (ch == '}')
            esc = true;
        if (!esc) {
            push_u8(g->in, ch);
        }
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

static fault_handler gdb_fh;

void gdb_check_fault_handler(thread t)
{
    if (gdb_fh)
        t->context.fault_handler = gdb_fh;
}

buffer_handler init_gdb(heap h,
                        process p,
                        buffer_handler outh)
{
    gdb g = allocate_zero(h, sizeof(struct gdb));
    g->output_handler = outh;
    // why do I need three here?
    g->output = allocate_buffer(h, 256);
    g->send_buffer = allocate_buffer(h, 256);
    g->out = allocate_buffer(h, 256);
    g->in = allocate_buffer(h, 256);
    g->h = h;
    g->p = p;
    spin_lock(&p->threads_lock);
    g->t = struct_from_field(rbtree_find_first(p->threads), thread, n);
    spin_unlock(&p->threads_lock);
    g->fault_handler = (fault_handler)&p->fault_handler;
    gdb_fh = closure(h, gdb_handle_exception, g);
    gdb_check_fault_handler(g->t);
    reset_parser(g);
    return closure(h, gdbserver_input, g);
}
