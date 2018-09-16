#pragma once
typedef closure_type(new_connection, buffer_handler, buffer_handler);
typedef closure_type(errno_handler, void, int);
void connection(heap h,
                descriptor e,
                buffer target,
                new_connection c,
                errno_handler failure);
void listen_port(heap h, descriptor e, u16 port, new_connection);
void epoll_spin(descriptor e);

