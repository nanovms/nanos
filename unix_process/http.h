
typedef closure_type(http_response, void, tuple);

buffer_handler allocate_http_parser(heap h, value_handler each);

void http_request(buffer_handler bh, tuple headers);
void send_http_response(buffer_handler out,
                        tuple t,
                        buffer c);
