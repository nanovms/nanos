#include <unix_internal.h>
#include <drivers/console.h>
#include <filesystem.h>
#include <lwip.h>
#include <mktime.h>

#define __STRING(x)     #x
#define __XSTRING(x)    __STRING(x)

#define SYSLOG_BUF_LEN  (8 * KB)

#define SYSLOG_FLUSH_INTERVAL   seconds(1)

#define SYSLOG_FILE_MAXSIZE_DEFAULT (8 * MB)

#define SYSLOG_FILE_ROTATE_DEFAULT  1
#define SYSLOG_FILE_ROTATE_MAX      9

/* facility: 1 (user-level messages)
 * severity: 6 (informational messages)
 * priority = facility * 8 + severity
 */
#define SYSLOG_PRIORITY 14

#define SYSLOG_VERSION  "1"

#define SYSLOG_UDP_PORT_DEFAULT 514

#define SYSLOG_UDP_MSG_MAX  8192

typedef struct syslog_udp_msg {
    struct list l;
    bytes len;
    timestamp t;
    struct pbuf_custom p;
    u8 buf[PBUF_TRANSPORT];
} *syslog_udp_msg;

#define syslog_lock()   u64 _irqflags = spin_lock_irq(&syslog.lock)
#define syslog_unlock() spin_unlock_irq(&syslog.lock, _irqflags)

static struct {
    struct console_driver driver;
    heap h;
    buffer file_path;
    u64 file_max_size;
    u64 file_rotate;
    fsfile fsf;
    sg_io fs_write;
    u64 file_offset;
    sg_list file_sg;
    sg_buf file_sgb;
    struct timer flush_timer;
    closure_struct(timer_handler, flush);
    closure_struct(shutdown_handler, shutdown);
    buffer program;
    sstring server;
    boolean dns_in_progress;
    boolean arp_init;
    timestamp dns_backoff;
    timestamp dns_req_next;
    ip_addr_t server_ip;
    u16 server_port;
    struct udp_pcb *udp_pcb;
    char local_ip[40];
    bytes local_ip_len;
    bytes max_hdr_len;
    bytes hdr_len;
    struct list udp_msgs;
    u64 udp_msg_count;
    struct spinlock lock;
} syslog;

static void syslog_file_rotate(void)
{
    sstring file_path = buffer_to_sstring(syslog.file_path);
    bytes path_len = file_path.len;
    sstring old_file = isstring(stack_allocate(path_len + 2), path_len + 2);
    sstring new_file = isstring(stack_allocate(path_len + 2), path_len + 2);
    runtime_memcpy(old_file.ptr, file_path.ptr, path_len);
    runtime_memcpy(new_file.ptr, file_path.ptr, path_len);
    old_file.ptr[path_len] = new_file.ptr[path_len] = '.';

    /* Rename rotated log files by replacing the ".<n-1>" name extension with ".<n>". */
    for (u64 i = syslog.file_rotate; i > 1; i--) {
        new_file.ptr[path_len + 1] = '0' + i - 1;
        old_file.ptr[path_len + 1] = '0' + i;
        fs_rename(new_file, old_file);
    }

    /* Rename the current log file by adding a ".1" extension to the file name. */
    old_file.ptr[path_len + 1] = '1';
    sysreturn ret = fs_rename(file_path, old_file);
    fsfile_release(syslog.fsf);

    if (ret == 0) {
        /* Continue logging on a new file. */
        syslog.fsf = fsfile_open_or_create(file_path, true);
        syslog.file_offset = 0;
        syslog.fs_write = fsfile_get_writer(syslog.fsf);
    } else {
        syslog.fs_write = 0;    /* stop logging */
    }
}

closure_function(4, 1, void, syslog_file_write_complete,
                 void *, buf, u64, len, sg_list, sg, status_handler, complete,
                 status s)
{
    fsfile f = syslog.fsf;
    status_handler complete = bound(complete);
    if (is_ok(s)) {
        fetch_and_add(&syslog.file_offset, bound(len));
        if (syslog.file_offset >= syslog.file_max_size) {
            /* Avoid deadlock in case a write completion occurs synchronously. */
            boolean unlock = spin_try(&syslog.lock);

            if (syslog.file_rotate > 0) {
                syslog_file_rotate();
            } else {
                /* Delete old logs instead of rotating. */
                if (fsfile_truncate(syslog.fsf, 0) == FS_STATUS_OK) {
                    syslog.file_offset = 0;
                } else {
                    fsfile_release(syslog.fsf);
                    syslog.fs_write = 0;    /* stop logging */
                }
            }
            if (unlock)
                spin_unlock(&syslog.lock);
        }
    } else if (!complete) {
        timm_dealloc(s);
    }
    deallocate(syslog.h, bound(buf), SYSLOG_BUF_LEN);
    deallocate_sg_list(bound(sg));
    closure_finish();
    if (complete) {
        if (is_ok(s))
            pagecache_sync_node(fsfile_get_cachenode(f), complete);
        else
            apply(complete, s);
    }
}

static void syslog_file_flush(status_handler complete)
{
    syslog_lock();
    sg_list sg = syslog.file_sg;
    if (sg) {
        syslog.file_sg = 0;
        u64 len = syslog.file_sgb->offset;
        status_handler sh =
                closure(syslog.h, syslog_file_write_complete, syslog.file_sgb->buf, len, sg,
                        complete);
        if (sh != INVALID_ADDRESS) {
            syslog.file_sgb->offset = 0;
            apply(syslog.fs_write, sg, irangel(syslog.file_offset, len), sh);
        } else {
            /* Discard logged data. */
            deallocate(syslog.h, syslog.file_sgb->buf, SYSLOG_BUF_LEN);
            deallocate_sg_list(sg);
            if (complete)
                apply(complete, timm("result", "failed to allocate completion"));
        }
    } else if (complete) {
        apply(complete, STATUS_OK);
    }
    syslog_unlock();
}

static void syslog_file_write(const char *s, bytes count)
{
    if (!syslog.fs_write || (count > SYSLOG_BUF_LEN))
        return;
    if (!syslog.file_sg) {
        syslog.file_sg = allocate_sg_list();
        if (syslog.file_sg == INVALID_ADDRESS)
            return;
        syslog.file_sgb = sg_list_tail_add(syslog.file_sg, SYSLOG_BUF_LEN);
        if (syslog.file_sgb == INVALID_ADDRESS) {
            deallocate_sg_list(syslog.file_sg);
            syslog.file_sg = 0;
            return;
        }
        syslog.file_sgb->buf = allocate(syslog.h, SYSLOG_BUF_LEN);
        if (syslog.file_sgb->buf == INVALID_ADDRESS) {
            deallocate_sg_list(syslog.file_sg);
            syslog.file_sg = 0;
            return;
        }
        syslog.file_sgb->size = SYSLOG_BUF_LEN;
        syslog.file_sgb->offset = 0;
        syslog.file_sgb->refcount = 0;
    }
    if (syslog.file_sgb->offset + count <= SYSLOG_BUF_LEN) {
        runtime_memcpy(syslog.file_sgb->buf + syslog.file_sgb->offset, s, count);
        syslog.file_sgb->offset += count;
        if (!timer_is_active(&syslog.flush_timer)) {
            register_timer(kernel_timers, &syslog.flush_timer, CLOCK_ID_MONOTONIC,
                                  SYSLOG_FLUSH_INTERVAL, false, 0,
                                  (timer_handler)&syslog.flush);
        }
    } else {
        syslog_file_flush(0);
        syslog_file_write(s, count);
    }
}

static void syslog_dns_failure(void)
{
    if (syslog.dns_backoff == 0)
        syslog.dns_backoff = seconds(1);
    else if (syslog.dns_backoff < seconds(60))
        syslog.dns_backoff *= 2;
    syslog.dns_req_next = kern_now(CLOCK_ID_MONOTONIC) + syslog.dns_backoff;
}

static void syslog_set_hdr_len(void)
{
    struct netif *n = netif_get_default();
    if (!n)
        return;
    syslog.local_ip_len = ipaddr_ntoa_r(&n->ip_addr, syslog.local_ip, sizeof(syslog.local_ip));
    netif_unref(n);
    syslog.hdr_len = syslog.max_hdr_len - sizeof(syslog.local_ip) +
                     syslog.local_ip_len + 1;
}

static void syslog_udp_send(void)
{
    u64 msg_count = 0;
    syslog_lock();
    list_foreach(&syslog.udp_msgs, e) {
        syslog_udp_msg msg = struct_from_list(e, syslog_udp_msg, l);
        list_delete(e);
        u64 secs = sec_from_timestamp(msg->t);
        struct tm tm;
        gmtime_r(&secs, &tm);
        struct pbuf *pbuf = &msg->p.pbuf;
        pbuf_remove_header(pbuf, syslog.max_hdr_len - syslog.hdr_len);
        rsnprintf(pbuf->payload, syslog.hdr_len,
            "<" __XSTRING(SYSLOG_PRIORITY) ">" SYSLOG_VERSION
            " %d-%02d-%02dT%02d:%02d:%02d.%06dZ %s %b - - -",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
            usec_from_timestamp(msg->t) - secs * MILLION,
            isstring(syslog.local_ip, syslog.local_ip_len), syslog.program);

        /* Replace the string terminator inserted by rsnprintf() with the last character of the
         * header. */
        *(char *)(pbuf->payload + syslog.hdr_len - 1) = ' ';

        udp_sendto(syslog.udp_pcb, pbuf, &syslog.server_ip, syslog.server_port);
        pbuf_free(pbuf);
        msg_count++;
        if (syslog.arp_init && (msg_count == ARP_QUEUE_LEN)) {
            /* Limit the number of packets sent in the initial batch, when an ARP query is likely
             * needed to resolve the destination MAC address in the LAN (outgoing packets need to be
             * queued until an ARP response is received). */
            if (!list_empty(&syslog.udp_msgs) && !timer_is_active(&syslog.flush_timer))
                register_timer(kernel_timers, &syslog.flush_timer, CLOCK_ID_MONOTONIC,
                               SYSLOG_FLUSH_INTERVAL, false, 0, (timer_handler)&syslog.flush);
            break;
        }
    }
    syslog.udp_msg_count -= msg_count;
    syslog_unlock();
    if (syslog.arp_init)
        syslog.arp_init = false;
}

static void syslog_dns_cb(sstring name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr) {
        syslog.server_ip = *ipaddr;
        syslog_udp_send();
    } else {
        syslog_dns_failure();
    }
    syslog.dns_in_progress = false;
}

static void syslog_udp_flush(void)
{
    if (!syslog.hdr_len) {
        syslog_set_hdr_len();
        if (!syslog.hdr_len)
            return;
    }
    if (syslog.dns_in_progress || (kern_now(CLOCK_ID_MONOTONIC) < syslog.dns_req_next))
        return;
    err_t err = dns_gethostbyname(syslog.server, &syslog.server_ip, syslog_dns_cb, 0);
    switch (err) {
    case ERR_OK:
        syslog_udp_send();
        break;
    case ERR_INPROGRESS:
        syslog.dns_in_progress = true;
        break;
    default:
        syslog_dns_failure();
        break;
    }
}

static void syslog_udp_free(struct pbuf *p)
{
    syslog_udp_msg msg = struct_from_field(p, syslog_udp_msg, p);
    deallocate(syslog.h, msg, sizeof(*msg) + msg->len);
}

static void syslog_udp_write(const char *s, bytes count)
{
    if (syslog.udp_msg_count >= SYSLOG_UDP_MSG_MAX) /* too many buffered messages */
        return;
    syslog_udp_msg msg = allocate(syslog.h, sizeof(*msg) + syslog.max_hdr_len + count);
    if (msg == INVALID_ADDRESS)
        return;
    msg->len = syslog.max_hdr_len + count;
    msg->t = kern_now(CLOCK_ID_REALTIME);
    msg->p.custom_free_function = syslog_udp_free;
    pbuf_alloced_custom(PBUF_TRANSPORT, msg->len, PBUF_RAM, &msg->p, msg->buf,
                               PBUF_TRANSPORT + msg->len);
    runtime_memcpy(msg->buf + PBUF_TRANSPORT + syslog.max_hdr_len, s, count);
    syslog_lock();
    list_push_back(&syslog.udp_msgs, &msg->l);
    syslog.udp_msg_count++;
    if (!timer_is_active(&syslog.flush_timer)) {
        register_timer(kernel_timers, &syslog.flush_timer, CLOCK_ID_MONOTONIC,
                       SYSLOG_FLUSH_INTERVAL, false, 0, (timer_handler)&syslog.flush);
    }
    syslog_unlock();
}

static void syslog_write(void *d, const char *s, bytes count)
{
    if (syslog.file_path)
        syslog_file_write(s, count);
    if (!sstring_is_null(syslog.server))
        syslog_udp_write(s, count);
}

closure_func_basic(timer_handler, void, syslog_timer_func,
                   u64 expiry, u64 overruns)
{
    if (overruns != timer_disabled) {
        syslog_file_flush(0);
        syslog_udp_flush();
    }
}

closure_func_basic(shutdown_handler, void, syslog_shutdown_completion,
                   int status, merge m)
{
    syslog_file_flush(apply_merge(m));
    syslog_udp_flush();
}

closure_func_basic(binding_handler, boolean, syslog_cfg,
                   value s, value v)
{
    if (s == sym(file)) {
        if (!is_string(v)) {
            rprintf("invalid syslog file\n");
            return false;
        }
        syslog.file_path = v;
    } else if (s == sym(file_max_size)) {
        if (!is_string(v)) {
            rprintf("invalid syslog file max size\n");
            return false;
        }
        buffer b = alloca_wrap(v);
        if (!parse_int(b, 10, &syslog.file_max_size)) {
            rprintf("invalid syslog file max size\n");
            return false;
        }
        if (buffer_length(b) == 1) {
            char suffix = *(char *)buffer_ref(b, 0);
            u64 size;
            switch (suffix) {
            case 'k':
            case 'K':
                size = syslog.file_max_size * KB;
                break;
            case 'm':
            case 'M':
                size = syslog.file_max_size * MB;
                break;
            case 'g':
            case 'G':
                size = syslog.file_max_size * GB;
                break;
            default:
                rprintf("invalid syslog file max size suffix '%c'\n", suffix);
                return false;
            }
            if (size < syslog.file_max_size) {
                /* Size value cannot be represented in 64 bits. */
                rprintf("invalid syslog file max size\n");
                return false;
            }
            syslog.file_max_size = size;
        } else if (buffer_length(b) > 1) {
            rprintf("invalid syslog file max size\n");
            return false;
        }
    } else if (s == sym(file_rotate)) {
        if (!(is_string(v) || is_integer(v)) ||
            !u64_from_value(v, &syslog.file_rotate)) {
            rprintf("invalid syslog file rotate count\n");
            return false;
        } else if (syslog.file_rotate > SYSLOG_FILE_ROTATE_MAX) {
            rprintf("syslog file rotate count greater than %d not supported\n",
                SYSLOG_FILE_ROTATE_MAX);
            return false;
        }
    } else if (s == sym(server)) {
        if (!is_string(v)) {
            rprintf("invalid syslog server\n");
            return false;
        }
        syslog.server = buffer_to_sstring(v);
    } else if (s == sym(server_port)) {
        u64 port;
        if (!(is_string(v) || is_integer(v)) ||
            !u64_from_value(v, &port) || (port > U16_MAX)) {
            rprintf("invalid syslog port\n");
            return false;
        }
        syslog.server_port = port;
    } else {
        rprintf("invalid syslog option '%v'\n", s);
        return false;
    }
    return true;
}

int init(status_handler complete)
{
    syslog.h = heap_locked(get_kernel_heaps());
    tuple root = get_root_tuple();
    tuple cfg = get(root, sym(syslog));
    if (!cfg) {
        rprintf("syslog configuration not specified\n");
        return KLIB_INIT_FAILED;
    }

    /* Default configuration option values */
    syslog.file_max_size = SYSLOG_FILE_MAXSIZE_DEFAULT;
    syslog.file_rotate = SYSLOG_FILE_ROTATE_DEFAULT;
    syslog.server_port = SYSLOG_UDP_PORT_DEFAULT;

    if (!is_tuple(cfg) || !iterate(cfg, stack_closure_func(binding_handler, syslog_cfg))) {
        rprintf("invalid syslog configuration\n");
        return KLIB_INIT_FAILED;
    }
    if (syslog.file_path) {
        syslog.fsf = fsfile_open_or_create(buffer_to_sstring(syslog.file_path), false);
        if (!syslog.fsf) {
            rprintf("cannot create syslog output file\n");
            return KLIB_INIT_FAILED;
        }
        syslog.fs_write = fsfile_get_writer(syslog.fsf);
        syslog.file_offset = fsfile_get_length(syslog.fsf); /* append to existing contents */
    }
    if (!sstring_is_null(syslog.server)) {
        tuple env = get_environment();
        syslog.program = get(env, sym(IMAGE_NAME));
        if (!syslog.program)
            syslog.program = get(root, sym(program));
        syslog.max_hdr_len = 1 + sizeof(__XSTRING(SYSLOG_PRIORITY)) + sizeof(SYSLOG_VERSION) +
                sizeof("YYYY-MM-ddThh:mm:ss.uuuuuuZ") + sizeof(syslog.local_ip) +
                buffer_length(syslog.program) + 7;
        syslog.udp_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
        if (!syslog.udp_pcb) {
            rprintf("syslog: unable to create UDP PCB\n");
            return KLIB_INIT_FAILED;
        }
        list_init(&syslog.udp_msgs);
        syslog.arp_init = true;
    }
    init_timer(&syslog.flush_timer);
    init_closure_func(&syslog.flush, timer_handler, syslog_timer_func);
    add_shutdown_completion(init_closure_func(&syslog.shutdown, shutdown_handler,
                                              syslog_shutdown_completion));
    syslog.driver.write = syslog_write;
    syslog.driver.name = ss("syslog");
    syslog.driver.disabled = false;
    attach_console_driver(&syslog.driver);
    return KLIB_INIT_OK;
}
