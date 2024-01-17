#include <unix_internal.h>
#include <filesystem.h>
#include <lwip.h>
#include <socket.h>

#define TUN_MINOR   200

/* ioctl requests */
#define TUNSETIFF   0x400454ca
#define TUNGETIFF   0x800454d2
#define TUNSETQUEUE 0x400454d9

/* ifreq flags */
#define IFF_TUN         0x0001
#define IFF_MULTI_QUEUE 0x0100

/* TUNSETQUEUE ifreq flags */
#define IFF_ATTACH_QUEUE 0x0200
#define IFF_DETACH_QUEUE 0x0400

#define TUN_TYPE_MASK   0x000f
#define IFF_NO_PI       0x1000

/* Packet information flags */
#define TUN_PKT_STRIP   0x0001

#define TUN_QUEUE_LEN   512

typedef struct tun_pi { /* packet information */
    u16 flags;
    u16 proto;  /* expressed in network byte order */
} *tun_pi;

typedef struct tun_file {
    file f;
    queue pq;  /* packet queue */
    blockq bq;
    struct list l;
    struct tun *tun;
    boolean attached;
} *tun_file;

typedef struct tun {
    struct spinlock lock;
    struct list files;
    short flags;
    struct netif netif;
    tun_file next_tx;
} *tun;

static heap tun_heap;
static tuple tun_cfg;

static void notify_events(fdesc f)
{
    u32 events = apply(f->events, 0);
    notify_dispatch(f->ns, events);
}

static err_t tun_if_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    tun t = netif->state;
    u64 min_ql = U64_MAX;
    tun_file selected = 0;
    int ret = ERR_WOULDBLOCK;
    spin_lock(&t->lock);
    tun_file f = t->next_tx;
    do {
        if (f->attached) {
            u64 len = queue_length(f->pq);
            if (len == 0) {
                selected = f;
                break;
            }
            if (len < min_ql) {
                selected = f;
                min_ql = len;
            }
        }
        list next = f->l.next;
        if (next == &t->files)
            next = next->next;
        f = struct_from_list(next, tun_file, l);
    } while (f != t->next_tx);
    if (selected && enqueue(selected->pq, p)) {
        pbuf_ref(p);
        if (blockq_wake_one(selected->bq) == INVALID_ADDRESS)
            notify_events(&selected->f->f);
        t->next_tx = selected;
        ret = ERR_OK;
    }
    spin_unlock(&t->lock);
    return ret;
}

static err_t tun_if_init(struct netif *netif)
{
    netif->output = tun_if_output;
    netif->mtu = 32 * KB;
    netif->flags = NETIF_FLAG_IGMP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

closure_function(4, 1, sysreturn, tun_read_bh,
                 tun_file, tf, void *, dest, u64, len, io_completion, completion,
                 u64, flags)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    sysreturn ret;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        ret = -ERESTARTSYS;
        goto out;
    }
    context ctx = get_current_context(current_cpu());
    struct pbuf *p = dequeue(tf->pq);
    if (p == INVALID_ADDRESS) {
        if (tf->f->f.flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto out;
        }
        return blockq_block_required((unix_context)ctx, flags);
    }
    void * dest = bound(dest);
    u64 len = bound(len);
    if (context_set_err(ctx)) {
        ret = -EFAULT;
        pbuf_free(p);
        goto out;
    }
    if (!(tun->flags & IFF_NO_PI)) {
        struct tun_pi pi;
        if (len < sizeof(pi)) {
            ret = -EINVAL;
            pbuf_free(p);
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
        runtime_memcpy(dest, &pi, sizeof(pi));
        dest += sizeof(pi);
        len -= sizeof(pi);
    }
    ret = MIN(len, p->tot_len);
    pbuf_copy_partial(p, dest, ret, 0);
    context_clear_err(ctx);
    pbuf_free(p);
    if (!(tun->flags & IFF_NO_PI))
        ret += sizeof(struct tun_pi);
  out:
    apply(bound(completion), ret);
    if (queue_empty(tf->pq))
        notify_events(&tf->f->f);
    closure_finish();
    return ret;
}

closure_function(1, 6, sysreturn, tun_read,
                 tun_file, tf,
                 void *, dest, u64, len, u64, offset_arg, context, ctx, boolean, bh, io_completion, completion)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    if (!tun)
        return io_complete(completion, -EBADFD);
    blockq_action ba = closure_from_context(ctx, tun_read_bh, tf, dest, len, completion);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, -ENOMEM);
    return blockq_check(tf->bq, ba, bh);
}

closure_function(1, 6, sysreturn, tun_write,
                 tun_file, tf,
                 void *, src, u64, len, u64, offset, context, ctx, boolean, bh, io_completion, completion)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    if (!tun)
        return io_complete(completion, -EBADFD);
    if (tun->flags & IFF_NO_PI) {
        if (len == 0)
            return io_complete(completion, -EINVAL);
    } else {
        if (len < sizeof(struct tun_pi))
            return io_complete(completion, -EINVAL);
        if (len == sizeof(struct tun_pi))
            return io_complete(completion, len);

        /* Discard packet information. */
        src += sizeof(struct tun_pi);
        len -= sizeof(struct tun_pi);
    }
    struct pbuf *p = pbuf_alloc(PBUF_LINK, len, PBUF_POOL);
    if (!p)
        return io_complete(completion, -ENOMEM);
    u64 copied = 0;
    struct pbuf *q = p;
    if (context_set_err(ctx)) {
        pbuf_free(p);
        return io_complete(completion, -EFAULT);
    }
    do {
        runtime_memcpy(q->payload, src + copied, q->len);
        copied += q->len;
        q = q->next;
    } while (q);
    context_clear_err(ctx);
    tun->netif.input(p, &tun->netif);
    if (!(tun->flags & IFF_NO_PI))
        len += sizeof(struct tun_pi);
    return io_complete(completion, len);
}

closure_function(1, 1, u32, tun_events,
                 tun_file, tf,
                 thread, t)
{
    tun_file tf = bound(tf);
    if (!tf->attached)
        return EPOLLERR;
    u32 events = EPOLLOUT;
    if (!queue_empty(tf->pq))
        events += EPOLLIN;
    return events;
}

static void get_tun_config(sstring name, ip4_addr_t *ipaddr, ip4_addr_t *netmask, u64 *mtu, boolean *bringup)
{
    if (!tun_cfg)
        return;
    tuple cfg = get_tuple(tun_cfg, sym_sstring(name));
    if (!cfg)
        return;
    buffer ipb = get(cfg, sym(ipaddress));
    if (ipb) {
        sstring ip = buffer_to_sstring(ipb);
        if (!ip4addr_aton(ip, ipaddr)) {
            rprintf("tun: invalid ipaddress %s\n", ip);
        }
    }
    buffer nmb = get(cfg, sym(netmask));
    if (nmb) {
        sstring nm = buffer_to_sstring(nmb);
        if (!ip4addr_aton(nm, netmask) || !ip4_addr_netmask_valid(netmask->addr)) {
            rprintf("tun: invalid netmask %s\n", nm);
        }
    }
    if (get_u64(cfg, sym(mtu), mtu)) {
        if (*mtu >= U64_FROM_BIT(16)) {
            rprintf("tun: invalid mtu %ld; ignored\n", *mtu);
            *mtu = 0;
        }
    }

    *bringup = get(cfg, sym(up)) != 0;
}

closure_function(1, 2, sysreturn, tun_ioctl,
                 tun_file, tf,
                 unsigned long, request, vlist, ap)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    switch (request) {
    case TUNSETIFF: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!fault_in_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        if (tun)
            return -EINVAL;
        switch (ifreq->ifr.ifr_flags & TUN_TYPE_MASK) {
        case IFF_TUN:
            break;
        default:
            return -EINVAL;
        }
        if ((ifreq->ifr.ifr_flags & ~TUN_TYPE_MASK) & ~(IFF_NO_PI | IFF_MULTI_QUEUE))
            return -EINVAL;
        struct netif *netif = netif_find(sstring_from_cstring(ifreq->ifr_name, IFNAMSIZ));
        if (netif) {
            boolean is_tun = (netif->output == tun_if_output);
            if (is_tun)
                tun = netif->state;
            netif_unref(netif);
            if (!is_tun)
                return -EINVAL;
        } else {
            tun = allocate(tun_heap, sizeof(struct tun));
            if (tun == INVALID_ADDRESS)
                return -ENOMEM;
            spin_lock_init(&tun->lock);
            tun->flags = ifreq->ifr.ifr_flags;
            if (ifreq->ifr_name[0] && ifreq->ifr_name[1]) {
                tun->netif.name[0] = ifreq->ifr_name[0];
                tun->netif.name[1] = ifreq->ifr_name[1];
            } else {    /* assign a default name */
                tun->netif.name[0] = 't';
                tun->netif.name[1] = 'u';
            }
            ip4_addr_t ipaddr = (ip4_addr_t){0};
            ip4_addr_t netmask = (ip4_addr_t){0};
            boolean bringup = false;
            u64 mtu = 0;
            sstring name = isstring(tun->netif.name, sizeof(tun->netif.name));
            get_tun_config(name, &ipaddr, &netmask, &mtu, &bringup);
            netif_add(&tun->netif, &ipaddr, &netmask, &ipaddr, tun, tun_if_init, netif_input);
            netif_name_cpy(ifreq->ifr_name, &tun->netif);
            list_init(&tun->files);
            tun->next_tx = tf;
            if (mtu > 0)
                tun->netif.mtu = mtu;
            if (bringup)
                netif_set_up(&tun->netif);
        }
        spin_lock(&tun->lock);
        list_push_back(&tun->files, &tf->l);
        tf->tun = tun;
        tf->attached = true;
        spin_unlock(&tun->lock);
        break;
    }
    case TUNGETIFF: {
        if (!tun)
            return -EBADFD;
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        context ctx = get_current_context(current_cpu());
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true) || context_set_err(ctx))
            return -EFAULT;
        netif_name_cpy(ifreq->ifr_name, &tun->netif);
        ifreq->ifr.ifr_flags = tun->flags;
        context_clear_err(ctx);
        break;
    }
    case TUNSETQUEUE: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        short flags;
        if (!get_user_value(&ifreq->ifr.ifr_flags, &flags))
            return -EFAULT;
        if ((flags & ~(IFF_ATTACH_QUEUE|IFF_DETACH_QUEUE)) ||
            (flags ^ (IFF_ATTACH_QUEUE|IFF_DETACH_QUEUE)) == 0)
            return -EINVAL;
        if (flags == IFF_ATTACH_QUEUE)
            tf->attached = true;
        else
            tf->attached = false;
        break;
    }
    default:
        return ioctl_generic(&tf->f->f, request, ap);
    }
    return 0;
}

closure_function(1, 2, sysreturn, tun_close,
                 tun_file, tf,
                 context, ctx, io_completion, completion)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    file f = tf->f;
    if (tun) {
        spin_lock(&tun->lock);
        list_delete(&tf->l);
        if (list_empty(&tun->files)) {
            spin_unlock(&tun->lock);
            netif_remove(&tun->netif);
            deallocate(tun_heap, tun, sizeof(struct tun_file));
            tun = 0;
        } else if (tun->next_tx == tf) {
            tun->next_tx = struct_from_list(tun->files.next, tun_file, l);
        }
        if (tun)
            spin_unlock(&tun->lock);
    }
    deallocate_blockq(tf->bq);
    deallocate_queue(tf->pq);
    deallocate_closure(f->f.read);
    deallocate_closure(f->f.write);
    deallocate_closure(f->f.events);
    deallocate_closure(f->f.ioctl);
    deallocate_closure(f->f.close);
    file_release(f);
    deallocate(tun_heap, tf, sizeof(struct tun_file));
    return io_complete(completion, 0);
}

closure_function(0, 1, sysreturn, tun_open,
                 file, f)
{
    tun_file tf = allocate(tun_heap, sizeof(struct tun_file));
    if (tf == INVALID_ADDRESS)
        return -ENOMEM;
    *tf = (struct tun_file){};
    f->f.read = closure(tun_heap, tun_read, tf);
    if (f->f.read == INVALID_ADDRESS)
        goto no_mem;
    f->f.write = closure(tun_heap, tun_write, tf);
    if (f->f.write == INVALID_ADDRESS)
        goto no_mem;
    f->f.events = closure(tun_heap, tun_events, tf);
    if (f->f.events == INVALID_ADDRESS)
        goto no_mem;
    f->f.ioctl = closure(tun_heap, tun_ioctl, tf);
    if (f->f.ioctl == INVALID_ADDRESS)
        goto no_mem;
    f->f.close = closure(tun_heap, tun_close, tf);
    if (f->f.close == INVALID_ADDRESS)
        goto no_mem;
    tf->pq = allocate_queue(tun_heap, TUN_QUEUE_LEN);
    if (tf->pq == INVALID_ADDRESS)
        goto no_mem;
    tf->bq = allocate_blockq(tun_heap, ss("tun"));
    if (tf->bq == INVALID_ADDRESS) {
        deallocate_queue(tf->pq);
        goto no_mem;
    }
    tf->f = f;
    tf->tun = 0;
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
    deallocate(tun_heap, tf, sizeof(struct tun_file));
    return -ENOMEM;
}

int init(status_handler complete)
{
    tun_heap = heap_locked(get_kernel_heaps());
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tun_cfg = get(root, sym(tun));
    if (tun_cfg && !is_tuple(tun_cfg)) {
        rprintf("invalid tun cfg\n");
        return KLIB_INIT_FAILED;
    }
    spec_file_open open = closure(tun_heap, tun_open);
    if (open == INVALID_ADDRESS)
        return KLIB_INIT_FAILED;
    if (create_special_file(ss("/dev/net/tun"), open, 0, makedev(MISC_MAJOR, TUN_MINOR))) {
        return KLIB_INIT_OK;
    } else {
        deallocate_closure(open);
        return KLIB_INIT_FAILED;
    }
}
