
typedef closure_type(http_response, void, tuple);
typedef closure_type(value_handler, void, value);

buffer_handler allocate_parser(heap h, value_handler each);
void http_request(buffer_handler bh, tuple headers);
buffer_handler http_transact(heap h, tuple req, buffer_handler send, value_handler v);

