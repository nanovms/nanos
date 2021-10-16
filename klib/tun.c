#include <unix_internal.h>
#include <lwip.h>
#include <socket.h>

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

#undef sym_this
#define sym_this(name)\
    (kfuncs.intern(alloca_wrap_buffer(name, runtime_strlen(name))))

#undef buffer_to_cstring
#define buffer_to_cstring(__b) ({                           \
            bytes len = buffer_length(__b);                 \
            char *str = stack_allocate(len + 1);            \
            kfuncs.runtime_memcpy(str, buffer_ref(__b, 0), len);   \
            str[len] = '\0';                                \
            str;                                            \
        })

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
static struct {
    sysreturn (*ioctl_generic)(fdesc f, unsigned long request, vlist ap);
    queue (*allocate_queue)(heap h, u64 size);
    boolean (*enqueue)(queue q, void *p);
    void *(*dequeue)(queue q);
    void (*deallocate_queue)(queue q);
    blockq (*allocate_blockq)(heap h, char *name);
    sysreturn (*blockq_check)(blockq bq, thread t, blockq_action a, boolean in_bh);
    thread (*blockq_wake_one)(blockq bq);
    void (*blockq_handle_completion)(blockq bq, u64 bq_flags, io_completion completion, thread t,
            sysreturn rv);
    void (*deallocate_blockq)(blockq bq);
    void (*lwip_lock)(void);
    void (*lwip_unlock)(void);
    struct netif *(*netif_add)(struct netif *netif,
            const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw,
            void *state, netif_init_fn init, netif_input_fn input);
    struct netif *(*netif_find)(const char *name);
    void (*netif_name_cpy)(char *dest, struct netif *netif);
    err_t (*netif_input)(struct pbuf *p, struct netif *inp);
    void (*netif_remove)(struct netif *netif);
    void (*netif_set_up)(struct netif *netif);
    struct pbuf *(*pbuf_alloc)(pbuf_layer layer, u16_t length, pbuf_type type);
    void (*pbuf_ref)(struct pbuf *p);
    u16 (*pbuf_copy_partial)(const struct pbuf *buf, void *dataptr, u16 len, u16 offset);
    u8 (*pbuf_free)(struct pbuf *p);
    void (*runtime_memcpy)(void *a, const void *b, bytes len);
    void (*file_release)(file f);
    symbol (*intern)(string name);
    int (*ip4addr_aton)(const char *cp, ip4_addr_t *addr);
    void *(*get)(value z, void *c);
    void (*rprintf)(const char *format, ...);
    void (*notify_dispatch)(notify_set s, u64 events);
    u8_t (*ip4_addr_netmask_valid)(u32_t netmask);
} kfuncs;

static void notify_events(fdesc f)
{
    u32 events = apply(f->events, 0);
    kfuncs.notify_dispatch(f->ns, events);
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
    if (selected && kfuncs.enqueue(selected->pq, p)) {
        kfuncs.pbuf_ref(p);
        if (kfuncs.blockq_wake_one(selected->bq) == INVALID_ADDRESS)
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

closure_function(5, 1, sysreturn, tun_read_bh,
                 tun_file, tf, void *, dest, u64, len, thread, t, io_completion, completion,
                 u64, flags)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    sysreturn ret;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        ret = -ERESTARTSYS;
        goto out;
    }
    struct pbuf *p = kfuncs.dequeue(tf->pq);
    if (p == INVALID_ADDRESS) {
        if (tf->f->f.flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    void * dest = bound(dest);
    u64 len = bound(len);
    boolean blocked = (flags & BLOCKQ_ACTION_BLOCKED) != 0;
    if (!(tun->flags & IFF_NO_PI)) {
        struct tun_pi pi;
        if (len < sizeof(pi)) {
            ret = -EINVAL;
            if (!blocked)
                kfuncs.lwip_lock();
            kfuncs.pbuf_free(p);
            if (!blocked)
                kfuncs.lwip_unlock();
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
    if (!blocked)
        kfuncs.lwip_lock();
    kfuncs.pbuf_copy_partial(p, dest, ret, 0);
    kfuncs.pbuf_free(p);
    if (!blocked)
        kfuncs.lwip_unlock();
    if (!(tun->flags & IFF_NO_PI))
        ret += sizeof(struct tun_pi);
  out:
    kfuncs.blockq_handle_completion(tf->bq, flags, bound(completion), bound(t), ret);
    if (queue_empty(tf->pq))
        notify_events(&tf->f->f);
    closure_finish();
    return ret;
}

closure_function(1, 6, sysreturn, tun_read,
                 tun_file, tf,
                 void *, dest, u64, len, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    if (!tun)
        return io_complete(completion, t, -EBADFD);
    blockq_action ba = closure(tun_heap, tun_read_bh, tf, dest, len, t, completion);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, t, -ENOMEM);
    return kfuncs.blockq_check(tf->bq, t, ba, bh);
}

closure_function(1, 6, sysreturn, tun_write,
                 tun_file, tf,
                 void *, src, u64, len, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    if (!tun)
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
    kfuncs.lwip_lock();
    struct pbuf *p = kfuncs.pbuf_alloc(PBUF_LINK, len, PBUF_POOL);
    kfuncs.lwip_unlock();
    if (!p)
        return io_complete(completion, t, -ENOMEM);
    u64 copied = 0;
    struct pbuf *q = p;
    do {
        kfuncs.runtime_memcpy(q->payload, src + copied, q->len);
        copied += q->len;
        q = q->next;
    } while (q);
    kfuncs.lwip_lock();
    tun->netif.input(p, &tun->netif);
    kfuncs.lwip_unlock();
    if (!(tun->flags & IFF_NO_PI))
        len += sizeof(struct tun_pi);
    return io_complete(completion, t, len);
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

static void get_tun_config(char *name, ip4_addr_t *ipaddr, ip4_addr_t *netmask, boolean *bringup)
{
    if (!tun_cfg)
        return;
    tuple cfg = kfuncs.get(tun_cfg, sym_this(name));
    if (!cfg || !is_tuple(cfg))
        return;
    buffer ipb = kfuncs.get(cfg, sym_intern(ipaddress, kfuncs.intern));
    if (ipb) {
        char *ip = buffer_to_cstring(ipb);
        if (!kfuncs.ip4addr_aton(ip, ipaddr)) {
            kfuncs.rprintf("tun: invalid ipaddress %s\n", ip);
        }
    }
    buffer nmb = kfuncs.get(cfg, sym_intern(netmask, kfuncs.intern));
    if (nmb) {
        char *nm = buffer_to_cstring(nmb);
        if (!kfuncs.ip4addr_aton(nm, netmask) || !kfuncs.ip4_addr_netmask_valid(netmask->addr)) {
            kfuncs.rprintf("tun: invalid netmask %s\n", nm);
        }
    }

    *bringup = kfuncs.get(cfg, sym_intern(up, kfuncs.intern)) != 0;
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
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
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
        kfuncs.lwip_lock();
        struct netif *netif = kfuncs.netif_find(ifreq->ifr_name);
        kfuncs.lwip_unlock();
        if (netif) {
            if (netif->output != tun_if_output)
                return -EINVAL;
            tun = netif->state;
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
            get_tun_config(tun->netif.name, &ipaddr, &netmask, &bringup);
            kfuncs.lwip_lock();
            kfuncs.netif_add(&tun->netif, &ipaddr, &netmask, &ipaddr, tun, tun_if_init, kfuncs.netif_input);
            kfuncs.netif_name_cpy(ifreq->ifr_name, &tun->netif);
            list_init(&tun->files);
            tun->next_tx = tf;
            if (bringup)
                kfuncs.netif_set_up(&tun->netif);
            kfuncs.lwip_unlock();
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
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        kfuncs.netif_name_cpy(ifreq->ifr_name, &tun->netif);
        ifreq->ifr.ifr_flags = tun->flags;
        break;
    }
    case TUNSETQUEUE: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), false))
            return -EFAULT;
        if ((ifreq->ifr.ifr_flags & ~(IFF_ATTACH_QUEUE|IFF_DETACH_QUEUE)) ||
                (ifreq->ifr.ifr_flags ^ (IFF_ATTACH_QUEUE|IFF_DETACH_QUEUE)) == 0)
            return -EINVAL;
        if (ifreq->ifr.ifr_flags == IFF_ATTACH_QUEUE)
            tf->attached = true;
        else
            tf->attached = false;
        break;
    }
    default:
        return kfuncs.ioctl_generic(&tf->f->f, request, ap);
    }
    return 0;
}

closure_function(1, 2, sysreturn, tun_close,
                 tun_file, tf,
                 thread, t, io_completion, completion)
{
    tun_file tf = bound(tf);
    tun tun = tf->tun;
    file f = tf->f;
    if (tun) {
        spin_lock(&tun->lock);
        list_delete(&tf->l);
        if (list_empty(&tun->files)) {
            spin_unlock(&tun->lock);
            kfuncs.lwip_lock();
            kfuncs.netif_remove(&tun->netif);
            kfuncs.lwip_unlock();
            deallocate(tun_heap, tun, sizeof(struct tun_file));
            tun = 0;
        } else if (tun->next_tx == tf) {
            tun->next_tx = struct_from_list(tun->files.next, tun_file, l);
        }
        if (tun)
            spin_unlock(&tun->lock);
    }
    kfuncs.deallocate_blockq(tf->bq);
    kfuncs.deallocate_queue(tf->pq);
    deallocate_closure(f->f.read);
    deallocate_closure(f->f.write);
    deallocate_closure(f->f.events);
    deallocate_closure(f->f.ioctl);
    deallocate_closure(f->f.close);
    kfuncs.file_release(f);
    deallocate(tun_heap, tf, sizeof(struct tun_file));
    return io_complete(completion, t, 0);
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
    tf->pq = kfuncs.allocate_queue(tun_heap, TUN_QUEUE_LEN);
    if (tf->pq == INVALID_ADDRESS)
        goto no_mem;
    tf->bq = kfuncs.allocate_blockq(tun_heap, "tun");
    if (tf->bq == INVALID_ADDRESS) {
        kfuncs.deallocate_queue(tf->pq);
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

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    void *(*get_kernel_heaps)(void);
    boolean (*create_special_file)(const char *path, spec_file_open open);
    tuple (*get_root_tuple)(void);
    if (!(get_kernel_heaps = get_sym("get_kernel_heaps")) ||
            !(create_special_file = get_sym("create_special_file")) ||
            !(get_root_tuple = get_sym("get_root_tuple")) ||
            !(kfuncs.rprintf = get_sym("rprintf")) ||
            !(kfuncs.ioctl_generic = get_sym("ioctl_generic")) ||
            !(kfuncs.allocate_queue = get_sym("allocate_queue")) ||
            !(kfuncs.enqueue = get_sym("enqueue")) ||
            !(kfuncs.dequeue = get_sym("dequeue")) ||
            !(kfuncs.deallocate_queue = get_sym("deallocate_queue")) ||
            !(kfuncs.allocate_blockq = get_sym("allocate_blockq")) ||
            !(kfuncs.blockq_check = get_sym("blockq_check")) ||
            !(kfuncs.blockq_wake_one = get_sym("blockq_wake_one")) ||
            !(kfuncs.blockq_handle_completion = get_sym("blockq_handle_completion")) ||
            !(kfuncs.deallocate_blockq = get_sym("deallocate_blockq")) ||
            !(kfuncs.lwip_lock = get_sym("lwip_lock")) ||
            !(kfuncs.lwip_unlock = get_sym("lwip_unlock")) ||
            !(kfuncs.netif_add = get_sym("netif_add")) ||
            !(kfuncs.netif_find = get_sym("netif_find")) ||
            !(kfuncs.netif_name_cpy = get_sym("netif_name_cpy")) ||
            !(kfuncs.netif_input = get_sym("netif_input")) ||
            !(kfuncs.netif_remove = get_sym("netif_remove")) ||
            !(kfuncs.netif_set_up = get_sym("netif_set_up")) ||
            !(kfuncs.pbuf_alloc = get_sym("pbuf_alloc")) ||
            !(kfuncs.pbuf_ref = get_sym("pbuf_ref")) ||
            !(kfuncs.pbuf_copy_partial = get_sym("pbuf_copy_partial")) ||
            !(kfuncs.pbuf_free = get_sym("pbuf_free")) ||
            !(kfuncs.runtime_memcpy = get_sym("runtime_memcpy")) ||
            !(kfuncs.file_release = get_sym("file_release")) ||
            !(kfuncs.ip4addr_aton = get_sym("ip4addr_aton")) ||
            !(kfuncs.get = get_sym("get")) ||
            !(kfuncs.notify_dispatch = get_sym("notify_dispatch")) ||
            !(kfuncs.ip4_addr_netmask_valid = get_sym("ip4_addr_netmask_valid")) ||
            !(kfuncs.intern = get_sym("intern")))
        return KLIB_INIT_FAILED;
    tun_heap = heap_locked(get_kernel_heaps());
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tun_cfg = kfuncs.get(root, sym_intern(tun, kfuncs.intern));
    if (tun_cfg && !is_tuple(tun_cfg)) {
        kfuncs.rprintf("invalid tun cfg\n");
        return KLIB_INIT_FAILED;
    }
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
