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

declare_closure_struct(0, 2, void, syslog_timer_func,
                       u64, expiry, u64, overruns);

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
    closure_struct(syslog_timer_func, flush);
    buffer program;
    char *server;
    boolean dns_in_progress;
    timestamp dns_backoff;
    timestamp dns_req_next;
    ip_addr_t server_ip;
    u16 server_port;
    struct udp_pcb *udp_pcb;
    char local_ip[40];
    bytes max_hdr_len;
    bytes hdr_len;
    struct list udp_msgs;
    u64 udp_msg_count;
    struct spinlock lock;
} syslog;

static struct {
    fsfile (*fsfile_open_or_create)(buffer file_path);
    sg_io (*fsfile_get_writer)(fsfile f);
    fs_status (*fsfile_truncate)(fsfile f, u64 len);
    sg_list (*allocate_sg_list)(void);
    sg_buf (*sg_list_tail_add)(sg_list sg, word length);
    void (*deallocate_sg_list)(sg_list sg);
    void (*runtime_memcpy)(void *a, const void *b, bytes len);
    void (*register_timer)(timer t, clock_id id, timestamp val, boolean absolute, timestamp interval,
            timer_handler n);
    void (*timm_dealloc)(tuple t);
    sysreturn (*fs_rename)(buffer oldpath, buffer newpath);
    void (*lwip_lock)(void);
    void (*lwip_unlock)(void);
    err_t (*dns_gethostbyname)(const char *hostname, ip_addr_t *addr,
            dns_found_callback found, void *callback_arg);
    struct netif *(*netif_get_default)(void);
    char *(*ipaddr_ntoa_r)(const ip_addr_t *addr, char *buf, int buflen);
    struct pbuf *(*pbuf_alloced_custom)(pbuf_layer l, u16_t length, pbuf_type type,
            struct pbuf_custom *p, void *payload_mem, u16_t payload_mem_len);
    u8_t (*pbuf_remove_header)(struct pbuf *p, size_t header_size);
    u8 (*pbuf_free)(struct pbuf *p);
    timestamp (*now)(clock_id id);
    struct tm *(*gmtime_r)(u64 *timep, struct tm *result);
    int (*rsnprintf)(char *str, u64 size, const char *fmt, ...);
    err_t(*udp_sendto)(struct udp_pcb *pcb, struct pbuf *p,
            const ip_addr_t *dst_ip, u16_t dst_port);
} kfuncs;

static void syslog_file_rotate(void)
{
    bytes path_len = buffer_length(syslog.file_path);
    buffer old_file = alloca_wrap_buffer(stack_allocate(path_len + 2), path_len + 2);
    buffer new_file = alloca_wrap_buffer(stack_allocate(path_len + 2), path_len + 2);
    kfuncs.runtime_memcpy(buffer_ref(old_file, 0), buffer_ref(syslog.file_path, 0), path_len);
    kfuncs.runtime_memcpy(buffer_ref(new_file, 0), buffer_ref(syslog.file_path, 0), path_len);
    byte(old_file, path_len) = byte(new_file, path_len) = '.';

    /* Rename rotated log files by replacing the ".<n-1>" name extension with ".<n>". */
    for (u64 i = syslog.file_rotate; i > 1; i--) {
        byte(new_file, path_len + 1) = '0' + i - 1;
        byte(old_file, path_len + 1) = '0' + i;
        kfuncs.fs_rename(new_file, old_file);
    }

    /* Rename the current log file by adding a ".1" extension to the file name. */
    byte(old_file, path_len + 1) = '1';
    sysreturn ret = kfuncs.fs_rename(syslog.file_path, old_file);

    if (ret == 0) {
        /* Continue logging on a new file. */
        fsfile file = kfuncs.fsfile_open_or_create(syslog.file_path);
        syslog.file_offset = 0;
        syslog.fs_write = kfuncs.fsfile_get_writer(file);
    } else {
        syslog.fs_write = 0;    /* stop logging */
    }
}

closure_function(3, 1, void, syslog_file_write_complete,
                 void *, buf, u64, len, sg_list, sg,
                 status, s)
{
    if (is_ok(s)) {
        fetch_and_add(&syslog.file_offset, bound(len));
        if (syslog.file_offset >= syslog.file_max_size) {
            /* Avoid deadlock in case a write completion occurs synchronously. */
            boolean unlock = spin_try(&syslog.lock);

            if (syslog.file_rotate > 0) {
                syslog_file_rotate();
            } else {
                /* Delete old logs instead of rotating. */
                if (kfuncs.fsfile_truncate(syslog.fsf, 0) == FS_STATUS_OK)
                    syslog.file_offset = 0;
                else
                    syslog.fs_write = 0;    /* stop logging */
            }
            if (unlock)
                spin_unlock(&syslog.lock);
        }
    } else {
        kfuncs.timm_dealloc(s);
    }
    deallocate(syslog.h, bound(buf), SYSLOG_BUF_LEN);
    kfuncs.deallocate_sg_list(bound(sg));
    closure_finish();
}

static void syslog_file_flush(void)
{
    syslog_lock();
    sg_list sg = syslog.file_sg;
    if (sg) {
        syslog.file_sg = 0;
        u64 len = syslog.file_sgb->offset;
        status_handler sh =
                closure(syslog.h, syslog_file_write_complete, syslog.file_sgb->buf, len, sg);
        if (sh != INVALID_ADDRESS) {
            syslog.file_sgb->offset = 0;
            apply(syslog.fs_write, sg, irangel(syslog.file_offset, len), sh);
        } else {
            /* Discard logged data. */
            deallocate(syslog.h, syslog.file_sgb->buf, SYSLOG_BUF_LEN);
            kfuncs.deallocate_sg_list(sg);
        }
    }
    syslog_unlock();
}

static void syslog_file_write(const char *s, bytes count)
{
    if (!syslog.fs_write || (count > SYSLOG_BUF_LEN))
        return;
    if (!syslog.file_sg) {
        syslog.file_sg = kfuncs.allocate_sg_list();
        if (syslog.file_sg == INVALID_ADDRESS)
            return;
        syslog.file_sgb = kfuncs.sg_list_tail_add(syslog.file_sg, SYSLOG_BUF_LEN);
        if (!syslog.file_sgb) {
            kfuncs.deallocate_sg_list(syslog.file_sg);
            syslog.file_sg = 0;
            return;
        }
        syslog.file_sgb->buf = allocate(syslog.h, SYSLOG_BUF_LEN);
        if (syslog.file_sgb->buf == INVALID_ADDRESS) {
            kfuncs.deallocate_sg_list(syslog.file_sg);
            syslog.file_sg = 0;
            return;
        }
        syslog.file_sgb->size = SYSLOG_BUF_LEN;
        syslog.file_sgb->offset = 0;
        syslog.file_sgb->refcount = 0;
    }
    if (syslog.file_sgb->offset + count <= SYSLOG_BUF_LEN) {
        kfuncs.runtime_memcpy(syslog.file_sgb->buf + syslog.file_sgb->offset, s, count);
        syslog.file_sgb->offset += count;
        if (!timer_is_active(&syslog.flush_timer)) {
            kfuncs.register_timer(&syslog.flush_timer, CLOCK_ID_MONOTONIC,
                                  SYSLOG_FLUSH_INTERVAL, false, 0,
                                  (timer_handler)&syslog.flush);
        }
    } else {
        syslog_file_flush();
        syslog_file_write(s, count);
    }
}

static void syslog_dns_failure(void)
{
    if (syslog.dns_backoff == 0)
        syslog.dns_backoff = seconds(1);
    else
        syslog.dns_backoff *= 2;
    syslog.dns_req_next = kfuncs.now(CLOCK_ID_MONOTONIC) + syslog.dns_backoff;
}

static void syslog_dns_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr)
        syslog.server_ip = *ipaddr;
    else
        syslog_dns_failure();
    syslog.dns_in_progress = false;
}

static void syslog_server_resolve(void)
{
    if (syslog.dns_in_progress || (kfuncs.now(CLOCK_ID_MONOTONIC) < syslog.dns_req_next))
        return;
    kfuncs.lwip_lock();
    err_t err = kfuncs.dns_gethostbyname(syslog.server, &syslog.server_ip, syslog_dns_cb, 0);
    kfuncs.lwip_unlock();
    switch (err) {
    case ERR_OK:
        break;
    case ERR_INPROGRESS:
        syslog.dns_in_progress = true;
        break;
    default:
        syslog_dns_failure();
        break;
    }
}

static void syslog_set_hdr_len(void)
{
    struct netif *n = kfuncs.netif_get_default();
    if (!n)
        return;
    kfuncs.ipaddr_ntoa_r(&n->ip_addr, syslog.local_ip, sizeof(syslog.local_ip));
    syslog.hdr_len = syslog.max_hdr_len - sizeof(syslog.local_ip) +
            runtime_strlen(syslog.local_ip) + 1;
}

static void syslog_udp_flush(void)
{
    if (ip_addr_isany_val(syslog.server_ip)) {
        syslog_server_resolve();
        return;
    }
    if (!syslog.hdr_len) {
        syslog_set_hdr_len();
        if (!syslog.hdr_len)
            return;
    }
    syslog_lock();
    list_foreach(&syslog.udp_msgs, e) {
        syslog_udp_msg msg = struct_from_list(e, syslog_udp_msg, l);
        list_delete(e);
        syslog.udp_msg_count--;
        u64 seconds = sec_from_timestamp(msg->t);
        struct tm tm;
        kfuncs.gmtime_r(&seconds, &tm);
        struct pbuf *pbuf = &msg->p.pbuf;
        kfuncs.pbuf_remove_header(pbuf, syslog.max_hdr_len - syslog.hdr_len);
        kfuncs.rsnprintf(pbuf->payload, syslog.hdr_len,
            "<" __XSTRING(SYSLOG_PRIORITY) ">" SYSLOG_VERSION
            " %d-%02d-%02dT%02d:%02d:%02d.%06dZ %s %b - - -",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
            usec_from_timestamp(msg->t) - seconds * MILLION, syslog.local_ip, syslog.program);

        /* Replace the string terminator inserted by rsnprintf() with the last character of the
         * header. */
        *(char *)(pbuf->payload + syslog.hdr_len - 1) = ' ';

        kfuncs.lwip_lock();
        kfuncs.udp_sendto(syslog.udp_pcb, pbuf, &syslog.server_ip, syslog.server_port);
        kfuncs.pbuf_free(pbuf);
        kfuncs.lwip_unlock();
    }
    syslog_unlock();
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
    msg->t = kfuncs.now(CLOCK_ID_REALTIME);
    msg->p.custom_free_function = syslog_udp_free;
    kfuncs.pbuf_alloced_custom(PBUF_TRANSPORT, msg->len, PBUF_RAM, &msg->p, msg->buf,
                               PBUF_TRANSPORT + msg->len);
    kfuncs.runtime_memcpy(msg->buf + PBUF_TRANSPORT + syslog.max_hdr_len, s, count);
    syslog_lock();
    list_push_back(&syslog.udp_msgs, &msg->l);
    syslog.udp_msg_count++;
    if (!timer_is_active(&syslog.flush_timer)) {
        kfuncs.register_timer(&syslog.flush_timer, CLOCK_ID_MONOTONIC, SYSLOG_FLUSH_INTERVAL, false,
                              0, (timer_handler)&syslog.flush);
    }
    syslog_unlock();
}

static void syslog_write(void *d, const char *s, bytes count)
{
    if (syslog.file_path)
        syslog_file_write(s, count);
    if (syslog.server)
        syslog_udp_write(s, count);
}

define_closure_function(0, 2, void, syslog_timer_func,
                        u64, expiry, u64, overruns)
{
    if (overruns != timer_disabled) {
        syslog_file_flush();
        syslog_udp_flush();
    }
}

closure_function(2, 2, boolean, syslog_cfg,
                 void *, intern, void *, rprintf,
                 value, s, value, v)
{
    symbol (*intern)(string name) = bound(intern);
    void (*rprintf)(const char *format, ...) = bound(rprintf);
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
        if (!is_string(v) || !u64_from_value(v, &syslog.file_rotate)) {
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
        bytes len = buffer_length(v);
        syslog.server = allocate(syslog.h, len + 1);
        if (syslog.server == INVALID_ADDRESS) {
            rprintf("unable to allocate memory for syslog server\n");
            return false;
        }
        kfuncs.runtime_memcpy(syslog.server, buffer_ref(v, 0), len);
        syslog.server[len] = '\0';
    } else if (s == sym(server_port)) {
        u64 port;
        if (!is_string(v) || !u64_from_value(v, &port) || (port > U16_MAX)) {
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

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    void (*rprintf)(const char *format, ...);
    if (!(rprintf = get_sym("rprintf")))
        return KLIB_INIT_FAILED;
    tuple (*get_root_tuple)(void) = get_sym("get_root_tuple");
    symbol (*intern)(string name) = get_sym("intern");
    value (*get)(value e, symbol a) = get_sym("get");
    boolean (*iterate)(value e, binding_handler h) = get_sym("iterate");
    u64 (*fsfile_get_length)(fsfile f) = get_sym("fsfile_get_length");
    void *(*get_kernel_heaps)(void) = get_sym("get_kernel_heaps");
    struct udp_pcb *(*udp_new)(void) = get_sym("udp_new");
    void (*attach_console_driver)(struct console_driver *driver) =
            get_sym("attach_console_driver");
    if (!get_root_tuple || !intern || !get || !iterate || !fsfile_get_length || !get_kernel_heaps ||
            !udp_new || !attach_console_driver ||
            !(kfuncs.fsfile_open_or_create = get_sym("fsfile_open_or_create")) ||
            !(kfuncs.fsfile_get_writer = get_sym("fsfile_get_writer")) ||
            !(kfuncs.fsfile_truncate = get_sym("fsfile_truncate")) ||
            !(kfuncs.allocate_sg_list = get_sym("allocate_sg_list")) ||
            !(kfuncs.sg_list_tail_add = get_sym("sg_list_tail_add")) ||
            !(kfuncs.deallocate_sg_list = get_sym("deallocate_sg_list")) ||
            !(kfuncs.runtime_memcpy = get_sym("runtime_memcpy")) ||
            !(kfuncs.register_timer = get_sym("kern_register_timer")) ||
            !(kfuncs.timm_dealloc = get_sym("timm_dealloc")) ||
            !(kfuncs.fs_rename = get_sym("fs_rename")) ||
            !(kfuncs.lwip_lock = get_sym("lwip_lock")) ||
            !(kfuncs.lwip_unlock = get_sym("lwip_unlock")) ||
            !(kfuncs.dns_gethostbyname = get_sym("dns_gethostbyname")) ||
            !(kfuncs.netif_get_default = get_sym("netif_get_default")) ||
            !(kfuncs.ipaddr_ntoa_r = get_sym("ipaddr_ntoa_r")) ||
            !(kfuncs.pbuf_alloced_custom = get_sym("pbuf_alloced_custom")) ||
            !(kfuncs.pbuf_remove_header = get_sym("pbuf_remove_header")) ||
            !(kfuncs.pbuf_free = get_sym("pbuf_free")) ||
            !(kfuncs.now = get_sym("now")) ||
            !(kfuncs.gmtime_r = get_sym("gmtime_r")) ||
            !(kfuncs.rsnprintf = get_sym("rsnprintf")) ||
            !(kfuncs.udp_sendto = get_sym("udp_sendto"))) {
        rprintf("syslog: kernel symbols not found\n");
        return KLIB_INIT_FAILED;
    }
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

    if (!is_tuple(cfg) || !iterate(cfg, stack_closure(syslog_cfg, intern, rprintf))) {
        rprintf("invalid syslog configuration\n");
        return KLIB_INIT_FAILED;
    }
    if (syslog.file_path) {
        syslog.fsf = kfuncs.fsfile_open_or_create(syslog.file_path);
        if (!syslog.fsf) {
            rprintf("cannot create syslog output file\n");
            return KLIB_INIT_FAILED;
        }
        syslog.fs_write = kfuncs.fsfile_get_writer(syslog.fsf);
        syslog.file_offset = fsfile_get_length(syslog.fsf); /* append to existing contents */
    }
    if (syslog.server) {
        syslog_server_resolve();
        syslog.program = get(root, sym(program));
        syslog.max_hdr_len = 1 + sizeof(__XSTRING(SYSLOG_PRIORITY)) + sizeof(SYSLOG_VERSION) +
                sizeof("YYYY-MM-ddThh:mm:ss.uuuuuuZ") + sizeof(syslog.local_ip) +
                buffer_length(syslog.program) + 7;
        kfuncs.lwip_lock();
        syslog.udp_pcb = udp_new();
        kfuncs.lwip_unlock();
        if (!syslog.udp_pcb) {
            rprintf("syslog: unable to create UDP PCB\n");
            return KLIB_INIT_FAILED;
        }
        list_init(&syslog.udp_msgs);
    }
    init_timer(&syslog.flush_timer);
    init_closure(&syslog.flush, syslog_timer_func);
    syslog.driver.write = syslog_write;
    syslog.driver.name = "syslog";
    syslog.driver.disabled = false;
    attach_console_driver(&syslog.driver);
    return KLIB_INIT_OK;
}
