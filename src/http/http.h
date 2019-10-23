typedef closure_type(http_response, void, tuple);
typedef closure_type(value_handler, void, value);

buffer_handler allocate_http_parser(heap h, value_handler each);
// just format the buffer?
status http_request(heap h, buffer_handler bh, tuple headers);
status send_http_response(buffer_handler out,
                          tuple t,
                          buffer c);
