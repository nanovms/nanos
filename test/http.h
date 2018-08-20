
typedef closure_type(http_response, void, tuple);
typedef closure_type(value_handler, void, value);
typedef closure_type(buffer_handler, void, buffer);

buffer_handler allocate_parser(heap h, value_handler each);
void http_request(buffer_handler bh, tuple headers);
buffer_handler http_transact(heap h, tuple req, buffer_handler send, value_handler v);
void send_http_response(buffer d, tuple t, buffer c);
