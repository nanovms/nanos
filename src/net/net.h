#define NET 1
#define NET_SYSCALLS 1

#define NET_NAPI_ID_MAGIC       0xAD000000
#define NET_NAPI_ID_MAGIC_MASK  0xFF000000
#define NET_NAPI_ID_IFACE_SHIFT 16

void init_net(kernel_heaps kh);
void init_network_iface(tuple root, merge m);
status listen_port(heap h, u16 port, connection_handler c);

static inline int net_get_napi_id(u8 iface_id, u16 queue_id)
{
    return (NET_NAPI_ID_MAGIC | ((u32)iface_id << NET_NAPI_ID_IFACE_SHIFT) | queue_id);
}
