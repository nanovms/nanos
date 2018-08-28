#define NET 1
#define NET_SYSCALLS 1

void register_net_syscalls(void **map);
boolean netsyscall_init(kernel k);
