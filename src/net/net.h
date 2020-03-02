#define NET 1
#define NET_SYSCALLS 1

boolean netsyscall_init(unix_heaps uh);
status listen_port(heap h, u16 port, connection_handler c);
