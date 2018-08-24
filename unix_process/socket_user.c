#include <runtime.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <socket_user.h>
#include <errno.h>

typedef struct registration {
    descriptor fd;
    thunk a;
}  *registration;
    
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


static CLOSURE_2_0(unreg, void, descriptor, descriptor);
static void unreg(descriptor e, descriptor f)
{
    rprintf("remove\n");
}

static void register_descriptor_write(heap h, descriptor e, descriptor f, thunk each)
{
    registration r = allocate(h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.ptr = r;    
    epoll_ctl(e, EPOLL_CTL_ADD, f, &ev);
}

static void register_descriptor(heap h, descriptor e, descriptor f, thunk each)
{
    registration r = allocate(h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    struct epoll_event ev;
    ev.events = EPOLLIN|EPOLLRDHUP|EPOLLET;
    ev.data.ptr = r;    
    epoll_ctl(e, EPOLL_CTL_ADD, f, &ev);
}

static CLOSURE_4_0(connection_input, void, heap, descriptor, descriptor, buffer_handler);
static void connection_input(heap h, descriptor f, descriptor e, buffer_handler p)
{
    buffer b = allocate_buffer(h, 512);
    b->end = read(f, b->contents, b->length);
    // this should have been taken care of by EPOLLHUP, but the
    // kernel doesn't support it
    if (!b->end) {
        epoll_ctl(e, EPOLL_CTL_DEL, f, 0);
        close(f);
    }
    apply(p, b);
}


static CLOSURE_1_1(connection_output, void, descriptor, buffer);
static void connection_output(descriptor c, buffer b)
{
    if (b)  {
        write(c, b->contents, buffer_length(b));
    } else {
        close(c);
    }
}

static CLOSURE_4_0(accepting, void, heap, descriptor, descriptor, new_connection);
static void accepting(heap h, descriptor e, descriptor c, new_connection n )
{
    struct sockaddr_in where;
    socklen_t len = sizeof(struct sockaddr_in);
    int s = accept(c, (struct sockaddr *)&where, &len);
    if (s < 0 ) halt("accept %E\n", errno);
    buffer_handler out = closure(h, connection_output, s);
    buffer_handler in = apply(n, out);
    register_descriptor(h, e, s, closure(h, connection_input, h, s, e, in));
}


static CLOSURE_4_0(connection_start, void, heap, descriptor, descriptor, new_connection);
void connection_start(heap h, descriptor s, descriptor e, new_connection c)
{
    buffer_handler out = closure(h, connection_output, s);
    buffer_handler input = apply(c, out);
    // dont stay for write
    epoll_ctl(e, EPOLL_CTL_DEL, s, 0);        
    register_descriptor(h, e, s, closure(h, connection_input, h, s, e, input));
}

// more general registration than epoll fd
// asynch
void connection(heap h, descriptor e, buffer target, new_connection c)
{
    struct sockaddr_in where;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    u32 v4;
    u16 port;
    parse_v4_address(alloca_wrap_buffer(buffer_ref(target, 0), buffer_length(target)),
                     &v4, &port);
    fill_v4_sockaddr(&where, v4, port);
    int status = connect(s, (struct sockaddr *)&where, sizeof(struct sockaddr_in));
    if (status < 0) halt("conection error %E", errno);

    register_descriptor_write(h, e, s, closure(h, connection_start, h, s, e, c));
}


void listen_port(heap h, descriptor e, u16 port, new_connection n)
{
    struct sockaddr_in where;

    descriptor service = socket(AF_INET, SOCK_STREAM, 0);
    memset(&where.sin_addr, 0, sizeof(unsigned int));
    where.sin_family = AF_INET;
    where.sin_port = htons(8080);
    if (setsockopt(service, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
    
    if (bind(service, (struct sockaddr *)&where, sizeof(struct sockaddr_in))) halt("bind %E", errno);
    if (listen(service, 5)) halt("listen %E", errno);

    register_descriptor(h, e, service, closure(h, accepting, h, e, service, n));
}


void epoll_spin(descriptor e)
{
    struct epoll_event ev[10];
    while (1) {
        int res = epoll_wait(e, ev, sizeof(ev)/sizeof(struct epoll_event), -1);
        if (res == -1) halt ("epoll %E", errno);
        for (int i = 0;i < res; i++) {
            registration r = ev[i].data.ptr;
            if (ev[i].events & EPOLLHUP)  {
                epoll_ctl(e, EPOLL_CTL_DEL, r->fd, 0);
                // always the right thing to do?
                close(r->fd);
            } else {
                apply(r->a);
            }
        }
    }
}

