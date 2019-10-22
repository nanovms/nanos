#pragma once
#define NET 1
#define NET_SYSCALLS 1

boolean netsyscall_init(unix_heaps uh);
typedef closure_type(connection_handler, buffer_handler, buffer_handler);
void listen_port(heap h, u16 port, connection_handler c);
