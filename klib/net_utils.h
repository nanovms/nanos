#ifndef NET_UTILS_H_
#define NET_UTILS_H_

#include <http.h>
#include <lwip/ip_addr.h>

typedef struct net_http_req_params {
    sstring host;
    tuple req;
    buffer body;
    value_handler resp_handler;
    http_method method;
    u16 port;
    boolean tls;
} *net_http_req_params;

void net_resolve(sstring host, void (*cb)(sstring host, const ip_addr_t *addr, void *cb_arg),
                 void *cb_arg);

boolean net_uri_encode(buffer dest, char *src, bytes len);

status net_http_req(net_http_req_params params);

#endif
