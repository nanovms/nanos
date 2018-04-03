#include <sruntime.h>
#include <gdbutil.h>

void gdb_send(pcb *pcb, buffer b)
{
    lwip_tcp_send();
}

void gdb_accept(gdb g, pcb *pcb, buffer b)
{
    lwip_tcp_send();
}

void init_gdb_tcp(heap h, process p)
{
    gdb g = init_gdb();
    int s = socket(0, 0, 0);
    bind(s);
    listen(s, 5);
    fd = accept();
    buffer_handler d = init_gdb(heap h, buffer_handler outh);
        
}
