typedef enum {
    HTTP_REQUEST_METHOD_GET = 0,
    HTTP_REQUEST_METHOD_HEAD,
    HTTP_REQUEST_METHOD_POST,
    HTTP_REQUEST_METHOD_PUT,
    HTTP_REQUEST_METHOD_DELETE,
    HTTP_REQUEST_METHOD_TRACE,
    HTTP_REQUEST_METHOD_OPTIONS,
    HTTP_REQUEST_METHOD_CONNECT,
    HTTP_REQUEST_METHOD_PATCH,
    HTTP_REQUEST_METHODS
} http_method;

typedef closure_type(http_response, void, tuple);

typedef struct http_responder *http_responder;

buffer_handler allocate_http_parser(heap h, value_handler each);
// just format the buffer?
status http_request(heap h, buffer_handler bh, http_method method,
                    tuple headers, buffer body);
status send_http_response(http_responder out,
                          tuple t,
                          buffer c);
status send_http_chunk(http_responder out, buffer c);
status send_http_chunked_response(http_responder out, tuple t);
status send_http_response(http_responder out, tuple t, buffer c);

extern const sstring http_request_methods[];

typedef struct http_listener *http_listener;
typedef closure_type(http_request_handler, void, http_method, http_responder, value);

void http_register_uri_handler(http_listener hl, sstring uri, http_request_handler each);
void http_register_default_handler(http_listener hl, http_request_handler each);
connection_handler connection_handler_from_http_listener(http_listener hl);
http_listener allocate_http_listener(heap h, u16 port);
void deallocate_http_listener(heap h, http_listener hl);
