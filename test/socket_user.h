
typedef closure_type(new_connection, buffer_handler, buffer_handler);
void connection(heap h, descriptor e, buffer target, new_connection c);
void listen_port(heap h, descriptor e, u16 port, new_connection);
void epoll_spin(descriptor e);

