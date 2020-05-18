#define NET 1
#define NET_SYSCALLS 1

boolean netsyscall_init(unix_heaps uh);
void init_network_iface(tuple root);
status listen_port(heap h, u16 port, connection_handler c);
