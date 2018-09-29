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
#include <fcntl.h>
#include <ip.h>
#include <arpa/inet.h> //htonl

typedef struct registration {
    descriptor fd;
    thunk a;
}  *registration;

void set_nonblocking(descriptor d)
{
    int flags = fcntl(d, F_GETFL);
    if (fcntl(d, F_SETFL, flags | O_NONBLOCK)) {
        halt("fcntl %E\n", errno);
    }
}

static void fill_v4_sockaddr(struct sockaddr_in *in, u32 address, u16 port)
{
    u32 p = htonl(address);
    memcpy(&in->sin_addr, &p, sizeof(u32));
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
}

buffer name_from_sockaddr_in (heap h, struct sockaddr_in *in)
{
    u32 x = htonl(*(u32*)&in->sin_addr);
    return aprintf(h, "%d.%d.%d.%d:%d",
                   (x>>24),
                   (x>>16) & 0xff,                  
                   (x>>8) & 0xff ,
                   x & 0xff,                  
                   htons(in->sin_port));
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

static void register_descriptor_except(heap h, descriptor e, descriptor f, thunk each)
{
    registration r = allocate(h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    struct epoll_event ev;
    ev.events = EPOLLERR;
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
    // can reuse?
    buffer b = allocate_buffer(h, 512);
    int res = read(f, b->contents, b->length);

    if (res < 0) {
        // should pass status
        apply(p, 0);
        return;
    }
    
    // this should have been taken care of by EPOLLHUP, but the
    // kernel doesn't support it        
    if (res == 0) {
        epoll_ctl(e, EPOLL_CTL_DEL, f, 0);
        close(f);
        apply(p, 0);
    } else {
        b->end = res;
        apply(p, b);
    }
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

tuple get_sockinfo(descriptor s)
{
    struct sockaddr_in sin;
    int len = sizeof(struct sockaddr_in);
    
    if (getsockname(s, (struct sockaddr *)&sin, &len) != 0)
        halt("Error on getsockname %E", errno);
    
    if (getpeername(s, (struct sockaddr *)&sin, &len) != 0)
        halt("Error on getpeername %E", errno);
}

static CLOSURE_4_0(accepting, void, heap, descriptor, descriptor, new_connection);
static void accepting(heap h, descriptor e, descriptor c, new_connection n)
{
    struct sockaddr_in where;
    socklen_t len = sizeof(struct sockaddr_in);
    int s = accept(c, (struct sockaddr *)&where, &len);
    get_sockinfo(s);
    if (s < 0 ) halt("accept %E\n", errno);
    buffer_handler out = closure(h, connection_output, s);
    buffer_handler in = apply(n, out);
    register_descriptor(h, e, s, closure(h, connection_input, h, s, e, in));
}

static CLOSURE_4_0(connection_start, void, heap, descriptor, descriptor, new_connection);
void connection_start(heap h, descriptor s, descriptor poll, new_connection c)
{
    buffer_handler out = closure(h, connection_output, s);
    buffer_handler input = apply(c, out);
    get_sockinfo(s);
    epoll_ctl(poll, EPOLL_CTL_DEL, s, 0);        
    register_descriptor(h, poll, s, closure(h, connection_input, h, s, poll, input));
}

static CLOSURE_3_0(connection_fail, void, descriptor, descriptor, status_handler);
void connection_fail(descriptor poll, descriptor s, status_handler failure)
{
    rprintf("connection fail\n");
    u32 result;
    u32 result_len = sizeof(result);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
        // could share code
        apply(failure, timmf("errno", "%d", result, "errstring", "%s", strerror(result)));
    } else {
        rprintf("errored socket with no error !?\n");
    }
    epoll_ctl(poll, EPOLL_CTL_DEL, s, 0);            
}

// more general registration than epoll fd
// asynch
void connection(heap h,
                descriptor poll,
                buffer target,
                new_connection c,
                status_handler failure)
{
    struct sockaddr_in where;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    u32 v4;
    u16 port;
    parse_v4_address_and_port(alloca_wrap(target), &v4, &port);
    fill_v4_sockaddr(&where, v4, port);
    set_nonblocking(s);
    int res = connect(s, (struct sockaddr *)&where, sizeof(struct sockaddr_in));
    int e = errno;
    // xxx - sometimes this was EAGAIN? EWOULDBLOCK?
    if (res && (e != EINPROGRESS)) {
        apply(failure, timmf("errno", "%d", errno,
                             "errstr", "%E", errno));
    } else {
        register_descriptor_write(h, poll, s, closure(h, connection_start, h, s, poll, c));
        register_descriptor_except(h, poll, s, closure(h, connection_fail, poll, s, failure));
    }
}


// should rety with asynch completion
void listen_port(heap h, descriptor e, u16 port, new_connection n)
{
    struct sockaddr_in where;

    descriptor service = socket(AF_INET, SOCK_STREAM, 0);
    memset(&where.sin_addr, 0, sizeof(unsigned int));
    where.sin_family = AF_INET;
    where.sin_port = htons(port);
    if (setsockopt(service, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
    
    if (bind(service, (struct sockaddr *)&where, sizeof(struct sockaddr_in)))
        halt("bind %E", errno);

    if (listen(service, 5))
        halt("listen %E", errno);

    register_descriptor(h, e, service, closure(h, accepting, h, e, service, n));
}


void epoll_spin(descriptor e)
{
    // make a 'notifier' abstraction to allow us to run the same code with epoll, select, kqeuue, etc
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

