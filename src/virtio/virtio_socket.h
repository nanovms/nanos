u32 virtio_sock_get_guest_cid(void *priv);
vsock_connection virtio_sock_conn_new(void *priv, u32 local_port, u32 peer_cid, u32 peer_port,
                                      u32 buf_size);
boolean virtio_sock_connect(vsock_connection conn);
boolean virtio_sock_connect_abort(vsock_connection conn);
void *virtio_sock_alloc_txbuf(void *priv, u64 size);
void virtio_sock_free_txbuf(void *priv, void *buf);
void virtio_sock_free_rxbuf(void *priv, void *buf);
u64 virtio_sock_get_buf_space(vsock_connection conn);
boolean virtio_sock_tx(vsock_connection conn, void *data);
void virtio_sock_recved(vsock_connection conn, u64 length);
boolean virtio_sock_shutdown(vsock_connection conn, int flags);
