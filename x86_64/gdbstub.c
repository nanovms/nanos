#include <sruntime.h>
#include <gdbutil.h>

static string output;
static string send_buffer;
static string out;
static string in;
static heap gh;
static interface client;
static context registers;

enum regnames {EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
	       PC /* also known as eip */,
	       PS /* also known as eflags */,
	       CS, SS, DS, ES, FS, GS};


CONTINUATION_1_2(actually, buffer, buffer, thunk);
static void actually(buffer o, buffer d, thunk s)
{
    memcpy(buffer_reference(d, 0),
           buffer_reference(o, 0),
           buffer_length(o));
    apply(s);
}

void gdb_send(string s)
{
    client->allocate_buffer(client, buffer_length(s), 
                            closure(gh, actually, s));
}


int signalmap[]={8, 5, 0, 5, 16, 16, 4, 8, 7, 11, 11, 11, 11, 11, 11, 0, 7};

int computeSignal (int exceptionVector)
{
    if (exceptionVector > (sizeof(signalmap)/sizeof(int))) 
        return(7);
    return(signalmap[exceptionVector]);
}

static int sigval;

void gdb_handle_exception (int exceptionVector, context c)
{
    sigval = computeSignal (exceptionVector);
    reset_buffer(output);
    /*
      byte swap
    bprintf (output, "T%02x%x:%08x;%x:%08x;%x:%08x;",
             sigval,
             ESP, c->esp,
             EBP, c->ebp,
             PC, c->eip);
    */
    bprintf (output, "T%02x",
             sigval);


    putpacket (send_buffer, output);
}

static void return_offsets(buffer in, string out)
{
    putpacket(send_buffer, out);
}

static void return_supported(buffer in, string out)
{
    putpacket(send_buffer, out);
}

static void current_thread(buffer in, string out)
{
    bprintf(out, "0");
    putpacket(send_buffer, output);
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

static void start_slave(context r, boolean stepping)
{
    
    if (stepping) {
        r->eflags |= 0x100;
    } else {
        r->eflags &= 0xfffffeff;
        // resume flag
        r->eflags |= (1<<16);
    }
    trap_frame = r;
    enter_user(r);
}


static void apply_vcont(buffer in, buffer out)
{
  u32 trash;

  if (check(in, ';')) {
    char kind = get_char(in);
    switch(kind) {
      case 'S':
        // step with signal?
        parse_int(in, 16, &trash);
      case 's':
        if (check(in,':')){
          u32 t;
          parse_int(in, 16, &t);
          start_slave(registers, 1);
        } else {
          start_slave(registers, 1);
        }
        break;

        break;
      case 't':
        break;
      case 'T':
         break;
      case 'C':{
         u32 sig;
         parse_int(in, 16, &sig);
         // what am i supposed to do with sig?
         start_slave(registers, 0);
      }
      case 'c':
       if (check(in,':')) {
          u32 t;
          parse_int(in, 16, &t);
          start_slave(registers, 0);
       } else {
          start_slave(registers, 0);
       }
    }
    apply_vcont(in, out);
  }
}


void return_support_conts(buffer in, string out)
{
  bprintf(out, "vCont;c;C;s;S;t;T");
  putpacket (send_buffer, out);
}

static struct handler v_handler[] = {
  {"Cont?", return_support_conts},
  {"Cont", apply_vcont},
  {0,0}
};


void bad_mem()
{
    bprintf(output, "E03");
    putpacket (send_buffer, output);
}


static void handle_request(buffer b)
{
    int addr, length;
    int stepping = 0;

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
        mem2hex (output, registers, sizeof(struct context));
        break;

    case 'G':		/* set the value of the CPU registers - return OK */
        hex2mem (b, (char *) registers, sizeof(struct context));
        bprintf (output, "OK");
        break;

    case 'H': /* set thread */
        bprintf (output, "OK");
        break;
        
    case 'q':
        handle_query(b, output, query_handler);
        break;
        
    case 'v':
        handle_query(b, output, v_handler);
        return;

    case 'p':
        bprintf(output, "00000000");
        break;

    case 'P':		/* set the value of a single CPU register - return OK */
        {
            int regno;
            if (parse_int (b, 16, &regno) && (get_char(b) == '='))                
                if (regno >= 0 && regno < (sizeof(struct context)/sizeof(u32))) {
                    // xxx - eah - sleeze
                    hex2mem (b, ((u32 *)registers) + regno, sizeof(u32));
                    bprintf (output, "OK");
                    break;
                }
            
            bprintf (output, "E01");
            break;
        }
        
        /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
    case 'm':
        if (parse_hex_pair(b, &addr, &length)) {
            page_fault_handler(bad_mem);
            if (!mem2hex (output, (char *) addr, length)) {
                bprintf(output, "E03");
            }
            page_fault_handler(0);    
            break;
        }
        bprintf(output, "E01");
        break;
        
        /* MAA..AA,LLLL: Write LLLL bytes at address AA.AA return OK */
    case 'M':
        /* TRY TO READ '%x,%x:'.  IF SUCCEED, SET PTR = 0 */
        if (parse_hex_pair(b, &addr, &length))
            if (get_char(b) == ':') {
                page_fault_handler(bad_mem);
                if (!hex2mem (b, (char *) addr, length)) {
                    bprintf(output, "E03");
                } else {
                    bprintf(output, "OK");
                    page_fault_handler(0);
                    break;
                }
                page_fault_handler(0);
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
            registers->eip = addr;
        start_slave(registers, stepping);
        break;
        
        /* kill the program */
    case 'k':		/* do nothing */
#if 0
        /* Huh? This doesn't look like "nothing".
           m68k-stub.c and sparc-stub.c don't have it.  */
        BREAKPOINT ();
#endif
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
    putpacket (send_buffer, output);
}

#define ASCII_CONTROL_C 0x03
void gdbserver_input(buffer b)
{
    unsigned char checksum;
    unsigned char xmitcsum;
    char ch = 0;

    reset_buffer(out);
    reset_buffer(in);

    /* wait around for the start character, ignore all other characters */
    while (buffer_length(b) && ((ch = get_char(b)) != '$')) {
        if (ch == ASCII_CONTROL_C) {
            gdb_handle_exception(1, registers);
            return;
        }
    }
 retry:
    checksum = 0;
    xmitcsum = -1;
  
    /* now, read until a # or end of buffer is found */
    while (buffer_length(b))
        {
            ch = get_char(b);
            // xxx - eah - workaround from trace, not the document
            if (ch == '$')
                goto retry;
            if (ch == '#')
                break;
            checksum = checksum + ch;
            string_insert(in, ch);
        }

    if (ch == '#') {
        ch = get_char(b);
        xmitcsum = digit_of(ch) << 4;
        ch = get_char(b);
        xmitcsum += digit_of(ch);
    
        if (checksum != xmitcsum)
            {
                string_insert(out, '-');	/* failed checksum */
            }
        else
            {
                string_insert(out, '+');	/* successful transfer */
            }
        gdb_send(out);
        handle_request(in);
        return;
    }
}

void init_gdb(heap h, 
              interface i,
              context r)
{
    output = allocate_string(h); 
    send_buffer = allocate_string(h); 
    out = allocate_string(h); 
    in = allocate_string(h); 
    gh = h;
    client = i;
    registers = r;
}
