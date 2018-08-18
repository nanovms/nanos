#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <unix_process_runtime.h>
#include <http.h>

// static inline boolean parse_int(buffer b, u32 base, u64 *result);

static boolean parse_v4_address(buffer b, u32 *u, u16 *port)
{
    u64 a;
    *u = 0;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;
    if (pop_u8(b) != '.') return false;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;    
    if (pop_u8(b) != '.') return false;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;        
    if (pop_u8(b) != '.') return false;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;            
    if (pop_u8(b) != ':') return false;    
    parse_int(b, 10, &a);
    *port = (u16)a;
    return true;
}

static void fill_v4_sockaddr(struct sockaddr_in *in, u32 address, u16 port)
{
    u32 p = htonl(address);
    memcpy(&in->sin_addr, &p, sizeof(u32));
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
}

static void register_descriptor(descriptor e, descriptor f, thunk each)
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = each;    
    epoll_ctl(e, EPOLL_CTL_ADD, f, &ev);
}

static CLOSURE_3_0(connection_input, void, heap, descriptor, buffer_handler)
static void connection_input(heap h, descriptor f, buffer_handler p)
{
    buffer b = allocate_buffer(h, 512);
    b->end = read(f, b->contents, b->length);
    apply(p, b);
}


static CLOSURE_1_1(connection_output, void, descriptor, buffer);
static void connection_output(descriptor c, buffer b)
{
    write(c, b->contents, buffer_length(b));
}

static CLOSURE_0_1(value_in, void, value);
static void value_in(value v)
{
    rprintf ("value in %v\n", v);
}

// asynch connection
static void create_connection(heap h, descriptor e, vector registrations, buffer target)
{
    struct sockaddr_in where;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    u32 v4;
    u16 port;
    parse_v4_address(target, &v4, &port);
    fill_v4_sockaddr(&where, v4, port);
    int status = connect(s, (struct sockaddr *)&where, sizeof(struct sockaddr_in));
    rprintf("Status %p\n", status);

    // chain events
    buffer_handler p = http_transact(h,
                                     timm("url", "/", "bogoheader", "zing"),
                                     closure(h, connection_output, s),
                                     closure(h, value_in));
    register_descriptor(e, s, closure(h, connection_input, h, s, p));
}


static void listener(vector registration)
{
    struct sockaddr_in where;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    
    if (bind(s, (struct sockaddr *)&where, sizeof(struct sockaddr_in))) {
        perror("bind:");
        exit(-1);
    }
    if (listen(s, 5)) {
        perror("listen:");
        exit(-1);
    }
}


void main(int argc, char **argv)
{
    heap h = init_process_runtime();
    int e = epoll_create(0);
    struct epoll_event ev[10];
    vector v = allocate_vector(h, 10);

    create_connection(h, e, v, alloca_wrap_buffer(argv[1], runtime_strlen(argv[1])));
    while (1) {
        int res = epoll_wait(e, ev, sizeof(ev)/sizeof(struct epoll_event), 0);
        for (int i = 0;i < res; i++) apply((thunk)ev[i].data.ptr);
    }
}

