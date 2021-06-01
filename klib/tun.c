#include <unix_internal.h>
#include <lwip.h>
#include <socket.h>

/* ioctl requests */
#define TUNSETIFF   0x400454ca
#define TUNGETIFF   0x800454d2

/* ifreq flags */
#define IFF_TUN         0x0001
#define TUN_TYPE_MASK   0x000f
#define IFF_NO_PI       0x1000

/* Packet information flags */
#define TUN_PKT_STRIP   0x0001

#define TUN_QUEUE_LEN   512

typedef struct tun_pi { /* packet information */
    u16 flags;
    u16 proto;  /* expressed in network byte order */
} *tun_pi;

typedef struct tun {
    file f;
    queue pq;  /* packet queue */
    blockq bq;
    short flags;
    struct netif *netif;
} *tun;

static heap tun_heap;
static struct {
    sysreturn (*ioctl_generic)(fdesc f, unsigned long request, vlist ap);
    queue (*allocate_queue)(heap h, u64 size);
    boolean (*enqueue)(queue q, void *p);
    void *(*dequeue)(queue q);
    void (*deallocate_queue)(queue q);
    blockq (*allocate_blockq)(heap h, char *name);
    sysreturn (*blockq_check)(blockq bq, thread t, blockq_action a, boolean in_bh);
    void (*blockq_handle_completion)(blockq bq, u64 bq_flags, io_completion completion, thread t,
            sysreturn rv);
    void (*deallocate_blockq)(blockq bq);
    struct netif *(*netif_add)(struct netif *netif,
            const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw,
            void *state, netif_init_fn init, netif_input_fn input);
    struct netif *(*netif_find)(const char *name);
    void (*netif_name_cpy)(char *dest, struct netif *netif);
    err_t (*netif_input)(struct pbuf *p, struct netif *inp);
    void (*netif_remove)(struct netif *netif);
    struct pbuf *(*pbuf_alloc)(pbuf_layer layer, u16_t length, pbuf_type type);
    void (*pbuf_ref)(struct pbuf *p);
    u16 (*pbuf_copy_partial)(const struct pbuf *buf, void *dataptr, u16 len, u16 offset);
    u8 (*pbuf_free)(struct pbuf *p);
    void (*runtime_memcpy)(void *a, const void *b, bytes len);
    void (*file_release)(file f);
} kfuncs;

static err_t tun_if_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    tun t = netif->state;
    if (kfuncs.enqueue(t->pq, p)) {
        kfuncs.pbuf_ref(p);
        return ERR_OK;
    } else {
        return ERR_WOULDBLOCK;
    }
}

static err_t tun_if_init(struct netif *netif)
{
    netif->output = tun_if_output;
    netif->mtu = 32 * KB;
    netif->flags = NETIF_FLAG_IGMP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

closure_function(5, 1, sysreturn, tun_read_bh,
                 tun, tun, void *, dest, u64, len, thread, t, io_completion, completion,
                 u64, flags)
{
    tun tun = bound(tun);
    sysreturn ret;
    struct pbuf *p = kfuncs.dequeue(tun->pq);
    if (p == INVALID_ADDRESS) {
        if (tun->f->f.flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    void * dest = bound(dest);
    u64 len = bound(len);
    if (!(tun->flags & IFF_NO_PI)) {
        struct tun_pi pi;
        if (len < sizeof(pi)) {
            ret = -EINVAL;
            kfuncs.pbuf_free(p);
            goto out;
        }
        if (len < p->tot_len + sizeof(pi))
            pi.flags = TUN_PKT_STRIP;
        else
            pi.flags = 0;
        int ip_version = IPH_V((struct ip_hdr *)p->payload);
        switch (ip_version) {
        case 4:
            pi.proto = htons(ETHTYPE_IP);
            break;
        case 6:
            pi.proto = htons(ETHTYPE_IPV6);
            break;
        }
        kfuncs.runtime_memcpy(dest, &pi, sizeof(pi));
        dest += sizeof(pi);
        len -= sizeof(pi);
    }
    ret = MIN(len, p->tot_len);
    kfuncs.pbuf_copy_partial(p, dest, ret, 0);
    kfuncs.pbuf_free(p);
    if (!(tun->flags & IFF_NO_PI))
        ret += sizeof(struct tun_pi);
  out:
    kfuncs.blockq_handle_completion(tun->bq, flags, bound(completion), bound(t), ret);
    closure_finish();
    return ret;
}

closure_function(1, 6, sysreturn, tun_read,
                 tun, tun,
                 void *, dest, u64, len, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    tun tun = bound(tun);
    if (!tun->netif)
        return io_complete(completion, t, -EBADFD);
    blockq_action ba = closure(tun_heap, tun_read_bh, bound(tun), dest, len, t, completion);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, t, -ENOMEM);
    return kfuncs.blockq_check(tun->bq, t, ba, bh);
}

closure_function(1, 6, sysreturn, tun_write,
                 tun, tun,
                 void *, src, u64, len, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    tun tun = bound(tun);
    if (!tun->netif)
        return io_complete(completion, t, -EBADFD);
    if (tun->flags & IFF_NO_PI) {
        if (len == 0)
            return io_complete(completion, t, -EINVAL);
    } else {
        if (len < sizeof(struct tun_pi))
            return io_complete(completion, t, -EINVAL);
        if (len == sizeof(struct tun_pi))
            return io_complete(completion, t, len);

        /* Discard packet information. */
        src += sizeof(struct tun_pi);
        len -= sizeof(struct tun_pi);
    }
    struct pbuf *p = kfuncs.pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (!p)
        return io_complete(completion, t, -ENOMEM);
    u64 copied = 0;
    struct pbuf *q = p;
    do {
        kfuncs.runtime_memcpy(q->payload, src + copied, q->len);
        copied += q->len;
        q = q->next;
    } while (q);
    tun->netif->input(p, tun->netif);
    if (!(tun->flags & IFF_NO_PI))
        len += sizeof(struct tun_pi);
    return len;
}

closure_function(1, 1, u32, tun_events,
                 tun, tun,
                 thread, t)
{
    tun tun = bound(tun);
    if (!tun->netif)
        return EPOLLERR;
    u32 events = EPOLLOUT;
    if (!queue_empty(tun->pq))
        events += EPOLLIN;
    return events;
}

closure_function(1, 2, sysreturn, tun_ioctl,
                 tun, tun,
                 unsigned long, request, vlist, ap)
{
    tun tun = bound(tun);
    switch (request) {
    case TUNSETIFF: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        if (tun->netif || kfuncs.netif_find(ifreq->ifr_name))
            return -EINVAL;
        switch (ifreq->ifr.ifr_flags & TUN_TYPE_MASK) {
        case IFF_TUN:
            break;
        default:
            return -EINVAL;
        }
        if ((ifreq->ifr.ifr_flags & ~TUN_TYPE_MASK) & ~IFF_NO_PI)
            return -EINVAL;
        tun->flags = ifreq->ifr.ifr_flags;
        tun->netif = allocate(tun_heap, sizeof(struct netif));
        if (tun->netif == INVALID_ADDRESS)
            return -ENOMEM;
        if (ifreq->ifr_name[0] && ifreq->ifr_name[1]) {
            tun->netif->name[0] = ifreq->ifr_name[0];
            tun->netif->name[1] = ifreq->ifr_name[1];
        } else {    /* assign a default name */
            tun->netif->name[0] = 't';
            tun->netif->name[1] = 'u';
        }
        tun->netif->state = tun;
        kfuncs.netif_add(tun->netif, 0, 0, 0, tun, tun_if_init, kfuncs.netif_input);
        kfuncs.netif_name_cpy(ifreq->ifr_name, tun->netif);
        break;
    }
    case TUNGETIFF: {
        if (!tun->netif)
            return -EBADFD;
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        kfuncs.netif_name_cpy(ifreq->ifr_name, tun->netif);
        ifreq->ifr.ifr_flags = tun->flags;
        break;
    }
    default:
        return kfuncs.ioctl_generic(&tun->f->f, request, ap);
    }
    return 0;
}

closure_function(1, 2, sysreturn, tun_close,
                 tun, tun,
                 thread, t, io_completion, completion)
{
    tun tun = bound(tun);
    file f = tun->f;
    if (tun->netif) {
        kfuncs.netif_remove(tun->netif);
        deallocate(tun_heap, tun->netif, sizeof(struct netif));
    }
    kfuncs.deallocate_blockq(tun->bq);
    kfuncs.deallocate_queue(tun->pq);
    deallocate_closure(f->f.read);
    deallocate_closure(f->f.write);
    deallocate_closure(f->f.events);
    deallocate_closure(f->f.ioctl);
    deallocate_closure(f->f.close);
    kfuncs.file_release(f);
    deallocate(tun_heap, tun, sizeof(struct tun));
    return io_complete(completion, t, 0);
}

closure_function(0, 1, sysreturn, tun_open,
                 file, f)
{
    tun t = allocate(tun_heap, sizeof(struct tun));
    if (t == INVALID_ADDRESS)
        return -ENOMEM;
    f->f.read = closure(tun_heap, tun_read, t);
    if (f->f.read == INVALID_ADDRESS)
        goto no_mem;
    f->f.write = closure(tun_heap, tun_write, t);
    if (f->f.write == INVALID_ADDRESS)
        goto no_mem;
    f->f.events = closure(tun_heap, tun_events, t);
    if (f->f.events == INVALID_ADDRESS)
        goto no_mem;
    f->f.ioctl = closure(tun_heap, tun_ioctl, t);
    if (f->f.ioctl == INVALID_ADDRESS)
        goto no_mem;
    f->f.close = closure(tun_heap, tun_close, t);
    if (f->f.close == INVALID_ADDRESS)
        goto no_mem;
    t->pq = kfuncs.allocate_queue(tun_heap, TUN_QUEUE_LEN);
    if (t->pq == INVALID_ADDRESS)
        goto no_mem;
    t->bq = kfuncs.allocate_blockq(tun_heap, "tun");
    if (t->bq == INVALID_ADDRESS) {
        kfuncs.deallocate_queue(t->pq);
        goto no_mem;
    }
    t->f = f;
    t->netif = 0;
    return 0;
  no_mem:
    if (f->f.read && (f->f.read != INVALID_ADDRESS))
        deallocate_closure(f->f.read);
    if (f->f.write && (f->f.write == INVALID_ADDRESS))
        deallocate_closure(f->f.write);
    if (f->f.events && (f->f.events == INVALID_ADDRESS))
        deallocate_closure(f->f.events);
    if (f->f.ioctl && (f->f.ioctl == INVALID_ADDRESS))
        deallocate_closure(f->f.ioctl);
    if (f->f.close && (f->f.close == INVALID_ADDRESS))
        deallocate_closure(f->f.close);
    deallocate(tun_heap, t, sizeof(struct tun));
    return -ENOMEM;
}

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    void *(*get_kernel_heaps)(void);
    boolean (*create_special_file)(const char *path, spec_file_open open);
    if (!(get_kernel_heaps = get_sym("get_kernel_heaps")) ||
            !(create_special_file = get_sym("create_special_file")) ||
            !(kfuncs.ioctl_generic = get_sym("ioctl_generic")) ||
            !(kfuncs.allocate_queue = get_sym("allocate_queue")) ||
            !(kfuncs.enqueue = get_sym("enqueue")) ||
            !(kfuncs.dequeue = get_sym("dequeue")) ||
            !(kfuncs.deallocate_queue = get_sym("deallocate_queue")) ||
            !(kfuncs.allocate_blockq = get_sym("allocate_blockq")) ||
            !(kfuncs.blockq_check = get_sym("blockq_check")) ||
            !(kfuncs.blockq_handle_completion = get_sym("blockq_handle_completion")) ||
            !(kfuncs.deallocate_blockq = get_sym("deallocate_blockq")) ||
            !(kfuncs.netif_add = get_sym("netif_add")) ||
            !(kfuncs.netif_find = get_sym("netif_find")) ||
            !(kfuncs.netif_name_cpy = get_sym("netif_name_cpy")) ||
            !(kfuncs.netif_input = get_sym("netif_input")) ||
            !(kfuncs.netif_remove = get_sym("netif_remove")) ||
            !(kfuncs.pbuf_alloc = get_sym("pbuf_alloc")) ||
            !(kfuncs.pbuf_ref = get_sym("pbuf_ref")) ||
            !(kfuncs.pbuf_copy_partial = get_sym("pbuf_copy_partial")) ||
            !(kfuncs.pbuf_free = get_sym("pbuf_free")) ||
            !(kfuncs.runtime_memcpy = get_sym("runtime_memcpy")) ||
            !(kfuncs.file_release = get_sym("file_release")))
        return KLIB_INIT_FAILED;
    tun_heap = heap_general(get_kernel_heaps());
    spec_file_open open = closure(tun_heap, tun_open);
    if (open == INVALID_ADDRESS)
        return KLIB_INIT_FAILED;
    if (create_special_file("/dev/net/tun", open)) {
        return KLIB_INIT_OK;
    } else {
        deallocate_closure(open);
        return KLIB_INIT_FAILED;
    }
}
