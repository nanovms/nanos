#define NET 1
#define NET_SYSCALLS 1

void init_net(kernel_heaps kh);
void init_network_iface(tuple root);
void ip4_when_ready(status_handler complete, timestamp timeout);
status listen_port(heap h, u16 port, connection_handler c);
