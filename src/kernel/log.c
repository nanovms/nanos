#include <kernel.h>
#include <log.h>
#include <storage.h>

#define KLOG_BUF_SIZE       KLOG_DUMP_SIZE
#define KLOG_BUF_SIZE_MASK  (KLOG_BUF_SIZE - 1)

#define KLOG_DUMP_MAGIC "KLOG"

declare_closure_struct(2, 1, void, klog_load_sh,
    klog_dump, dest, status_handler, sh,
    status, s);

static struct {
    char buf[KLOG_BUF_SIZE];
    bytes count;
    struct spinlock lock;
    u64 disk_offset;
    block_io disk_read, disk_write;
    closure_struct(klog_load_sh, load_sh);
    struct klog_dump dump;
} klog;

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

void klog_disk_setup(u64 disk_offset, block_io disk_read, block_io disk_write)
{
    klog.disk_offset = disk_offset;
    klog.disk_read = disk_read;
    klog.disk_write = disk_write;
}

void klog_set_boot_id(u64 id)
{
    klog.dump.boot_id = id;
}
KLIB_EXPORT(klog_set_boot_id);

define_closure_function(2, 1, void, klog_load_sh,
                        klog_dump, dest, status_handler, sh,
                        status, s)
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
    if (klog.disk_read)
        apply(klog.disk_read, dest,
              irangel(klog.disk_offset >> SECTOR_OFFSET, KLOG_DUMP_SIZE >> SECTOR_OFFSET),
              init_closure(&klog.load_sh, klog_load_sh, dest, sh));
}
KLIB_EXPORT(klog_load);

void klog_save(int exit_code, status_handler sh)
{
    if (!klog.disk_write) {
        apply(sh, STATUS_OK);
        return;
    }
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
    apply(klog.disk_write, &klog.dump,
        irangel(klog.disk_offset >> SECTOR_OFFSET, KLOG_DUMP_SIZE >> SECTOR_OFFSET), sh);
}

void klog_dump_clear(void)
{
    /* Make an invalid header. */
    zero(&klog.dump.header, sizeof(klog.dump.header));

    /* Only the first sector needs to be written. */
    apply(klog.disk_write, &klog.dump,
        irangel(klog.disk_offset >> SECTOR_OFFSET, 1), ignore_status);
}
KLIB_EXPORT(klog_dump_clear);
