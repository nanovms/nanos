#define VSOCK_SHUTDOWN_TX   U64_FROM_BIT(0)
#define VSOCK_SHUTDOWN_RX   U64_FROM_BIT(1)

typedef struct vsock_connection {
    struct vsock_conn_id {
        u32 local_port;
        u32 peer_cid;
        u32 peer_port;
    } id;
    void *vsock;
    void *bound;
    struct refcount refc;
    struct spinlock lock;
} *vsock_connection;

static inline void vsock_conn_init(vsock_connection conn, u32 local_port,
                                   u32 peer_cid, u32 peer_port, thunk free)
{
    conn->id.local_port = local_port;
    conn->id.peer_cid = peer_cid;
    conn->id.peer_port = peer_port;
    conn->bound = 0;
    init_refcount(&conn->refc, 1 , free);
    spin_lock_init(&conn->lock);
}

#define vsock_conn_lock(c)      spin_lock(&(c)->lock)
#define vsock_conn_unlock(c)    spin_unlock(&(c)->lock)

#define vsock_conn_release(c)   refcount_release(&(c)->refc)

void vsock_set_transport(void *transport);

u32 vsock_get_buf_size(void);

/* Functions returning a vsock_connection must return with the connection locked. */
boolean vsock_connect_request(vsock_connection conn);
vsock_connection vsock_connect_complete(struct vsock_conn_id *conn_id, boolean success);
vsock_connection vsock_get_conn(struct vsock_conn_id *conn_id);
vsock_connection vsock_rx(struct vsock_conn_id *conn_id, void *data, u64 len);
void vsock_buf_space_notify(vsock_connection conn, u64 buf_space);
vsock_connection vsock_shutdown_request(struct vsock_conn_id *conn_id, int flags,
                                        boolean *conn_close);
void vsock_conn_reset(struct vsock_conn_id *conn_id);
