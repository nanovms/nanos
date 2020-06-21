#define NET 1
#define NET_SYSCALLS 1

void init_network_iface(tuple root);
status listen_port(heap h, u16 port, connection_handler c);
