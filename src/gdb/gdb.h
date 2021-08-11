#define GDB 1

// thunk service?
void init_tcp_gdb(heap h, process p, u16 port);
void gdb_install_fault_handler(thread t);
