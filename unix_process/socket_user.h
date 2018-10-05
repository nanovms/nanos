
typedef closure_type(new_connection, buffer_handler, buffer_handler);
void connection(heap h,
		notifier n,
                buffer target,
                new_connection c,
                status_handler failure);
void listen_port(heap h, notifier n, u16 port, new_connection);
