#include <kernel.h>
#include <storage.h>

#define KLOG_BUF_SIZE       KLOG_DUMP_SIZE
#define KLOG_BUF_SIZE_MASK  (KLOG_BUF_SIZE - 1)

#define KLOG_DUMP_MAGIC "KLOG"

u64 trace_get_flags(value v)
{
    u64 flags = 0;
    if (v && is_string(v)) {
        buffer b = alloca_wrap((buffer)v);
        int delim;
        while (buffer_length(b) > 0) {
            delim = buffer_strchr(b, ',');
            u64 end = b->end;
            if (delim > 0)
                b->end = b->start + delim;
            if (delim) {
                if (!buffer_strcmp(b, "all"))
                    return -1ull;
                if (!buffer_strcmp(b, "threadrun"))
                    flags |= TRACE_THREAD_RUN;
                else if (!buffer_strcmp(b, "pf"))
                    flags |= TRACE_PAGE_FAULT;
                else
                    flags |= TRACE_OTHER;
                if (delim < 0)
                    break;
                b->end = end;
            }
            buffer_consume(b, delim + 1);
        }
    }
    return flags;
}

declare_closure_struct(2, 1, void, klog_load_sh,
    klog_dump, dest, status_handler, sh,
    status s);

static struct {
    struct klog_dump dump;
    char buf[KLOG_BUF_SIZE];
    bytes count;
    struct spinlock lock;
    u64 disk_offset;
    storage_req_handler disk_handler;
    closure_struct(klog_load_sh, load_sh);
} klog __attribute__ ((aligned(SECTOR_SIZE)));

#define klog_lock()     u64 _irqflags = spin_lock_irq(&klog.lock)
#define klog_unlock()   spin_unlock_irq(&klog.lock, _irqflags)

void klog_write(const char *s, bytes count)
{
    if (count > KLOG_BUF_SIZE) {
        /* Copy the last KLOG_BUF_SIZE bytes only. */
        s += count - KLOG_BUF_SIZE;
        count = KLOG_BUF_SIZE;
    }
    klog_lock();
    bytes index = klog.count & KLOG_BUF_SIZE_MASK;
    bytes limit = MIN(count, KLOG_BUF_SIZE - index);
    runtime_memcpy(&klog.buf[index], s, limit);
    if (limit < count)
        runtime_memcpy(klog.buf, s + limit, count - limit);
    klog.count += count;
    klog_unlock();
}

void klog_disk_setup(u64 disk_offset, storage_req_handler req_handler)
{
    klog.disk_offset = disk_offset;
    klog.disk_handler = req_handler;
}

void klog_set_boot_id(u64 id)
{
    klog.dump.boot_id = id;
}

define_closure_function(2, 1, void, klog_load_sh,
                        klog_dump, dest, status_handler, sh,
                        status s)
{
    klog_dump dest = bound(dest);
    if (is_ok(s) && runtime_memcmp(&dest->header, KLOG_DUMP_MAGIC, sizeof(KLOG_DUMP_MAGIC) - 1)) {
        /* There is no log dump. */
        dest->boot_id = dest->exit_code = 0;
        dest->msgs[0] = '\0';
    }
    apply(bound(sh), s);
}

void klog_load(klog_dump dest, status_handler sh)
{
    struct storage_req req = {
        .op = STORAGE_OP_READ,
        .blocks = range_rshift(irangel(klog.disk_offset, KLOG_DUMP_SIZE), SECTOR_OFFSET),
        .data = dest,
        .completion = init_closure(&klog.load_sh, klog_load_sh, dest, sh),
    };
    apply(klog.disk_handler, &req);
}

void klog_save(int exit_code, status_handler sh)
{
    bytes msg_len = 0;
    if (klog.count > 0) {
        klog_lock();
        msg_len = MIN(klog.count, sizeof(klog.dump.msgs) - 1);
        bytes index = (klog.count - msg_len) & KLOG_BUF_SIZE_MASK;
        bytes limit = MIN(msg_len, KLOG_BUF_SIZE - index);
        runtime_memcpy(klog.dump.msgs, &klog.buf[index], limit);
        if (limit < msg_len)
            runtime_memcpy(&klog.dump.msgs[limit], klog.buf, msg_len - limit);
        klog_unlock();
    }
    runtime_memcpy(&klog.dump.header, KLOG_DUMP_MAGIC, sizeof(KLOG_DUMP_MAGIC) - 1);
    klog.dump.msgs[msg_len] = '\0';
    klog.dump.exit_code = exit_code;
    struct storage_req req = {
        .op = STORAGE_OP_WRITE,
        .blocks = range_rshift(irangel(klog.disk_offset, KLOG_DUMP_SIZE), SECTOR_OFFSET),
        .data = &klog.dump,
        .completion = sh,
    };
    apply(klog.disk_handler, &req);
}

void klog_dump_clear(void)
{
    /* Make an invalid header. */
    zero(&klog.dump.header, sizeof(klog.dump.header));

    /* Only the first sector needs to be written. */
    struct storage_req req = {
        .op = STORAGE_OP_WRITE,
        .blocks = irangel(klog.disk_offset >> SECTOR_OFFSET, 1),
        .data = &klog.dump,
        .completion = ignore_status,
    };
    apply(klog.disk_handler, &req);
}
