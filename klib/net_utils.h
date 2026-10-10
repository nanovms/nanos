#ifndef NET_UTILS_H_
#define NET_UTILS_H_

#include <http.h>
#include <lwip/ip_addr.h>

#define FQDN_MAX_LEN        253             /* RFC 2181 */
#define EMAIL_ADDR_MAX_LEN  (64 + 1 + 255)  /* RFC 5321 */

typedef struct net_http_req_params {
    sstring host;
    sstring query;
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
boolean net_url_to_reqparams(sstring url, net_http_req_params params);

status net_http_req(net_http_req_params params);
status net_http_get(sstring url, tuple req, value_handler resp_handler);
status net_http_post(sstring url, tuple req, buffer body, value_handler resp_handler);

boolean base64url_encode(buffer dest, void *src, bytes len);

#endif
