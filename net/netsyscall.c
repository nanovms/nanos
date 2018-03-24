#include <sruntime.h>
#include <unix.h>

#include "lwip/init.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/apps/fs.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"

// the network portion of the syscall interface on top of lwip

typedef struct sock {
    // or..
    struct tcp_pcb *pcb;
} *sock;

// try keeping an overlay map instead of blowing out the fd closures, or having a type, or..
static socket sockfds[FDS];
    
int socket(int domain, int type, int protocol)
{
  pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  LWIP_ASSERT("httpd_init: tcp_new failed", pcb != NULL);
  tcp_setprio(pcb, HTTPD_TCP_PRIO);
  /* set SOF_REUSEADDR here to explicitly bind httpd to multiple interfaces */

  LWIP_UNUSED_ARG(err); /* in case of LWIP_NOASSERT */
  LWIP_ASSERT("httpd_init: tcp_bind failed", err == ERR_OK);
  pcb = tcp_listen(pcb);
  LWIP_ASSERT("httpd_init: tcp_listen failed", pcb != NULL);
  tcp_accept(pcb, http_accept);
}

int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
      err = tcp_bind(pcb, IP_ANY_TYPE, HTTPD_SERVER_PORT);
}

int connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
}

int listen(int sockfd, int backlog)
{
      pcb = tcp_listen(pcb);
}

static err_t accept_callback(void *arg, struct tcp_pcb *pcb, err_t err)
{
    socket s = arg;
    // child - allocate a new socket and an fd for it
}
    
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    socket s;
    tcp_accept(pcb, accept_callback, s);
}

// sendmsg, send, recv, etc..


