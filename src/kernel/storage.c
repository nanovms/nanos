#include <kernel.h>
#include <pagecache.h>
#include <storage.h>
#include <fs.h>

//#define STORAGE_DEBUG
#ifdef STORAGE_DEBUG
#define storage_debug(x, ...) do {tprintf(sym(storage), 0, ss(x "\n"), ##__VA_ARGS__);} while(0)
#else
#define storage_debug(x, ...)
#endif

typedef struct volume {
    struct list l;
    u8 uuid[UUID_LEN];
    char label[VOLUME_LABEL_MAX_LEN];
    bytes label_len;
    void *priv;
    fs_init_handler init_handler;
    int attach_id;
    boolean mounting;
    filesystem fs;
    inode mount_dir;
} *volume;

static struct {
    heap h;
    filesystem root_fs;
    struct list volumes;
    tuple mounts;
    boolean mounting;
    status_handler mount_complete;
    struct spinlock lock;
    u64 mount_generation;
    vector mounts_watchers;
} storage;

#define storage_lock()      u64 _irqflags = spin_lock_irq(&storage.lock)
#define storage_unlock()    spin_unlock_irq(&storage.lock, _irqflags)

static void notify_mount_change_locked(void);

/* Called with mutex locked. */
static volume storage_get_volume(tuple root)
{
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (v->fs && (filesystem_getroot(v->fs) == root)) {
            return v;
        }
    }
    return 0;
}

static void storage_check_if_ready(void)
{
    boolean mounting = false;
    status_handler complete = 0;
    storage_lock();
    if (!storage.mount_complete) {
        storage_unlock();
        return;
    }
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (v->mounting) {
            mounting = true;
            break;
        }
    }
    if (!mounting) {
        complete = storage.mount_complete;
        storage.mount_complete = 0;
    }
    storage_unlock();
    if (complete)
        apply(complete, STATUS_OK);
}

static boolean volume_match(symbol s, volume v)
{
    /* UUID format in symbol string: 00112233-4455-6677-8899-aabbccddeeff */
    buffer vol = symbol_string(s);
    if ((buffer_length(vol) > 1) && (peek_char(vol) == '%')) {
        /* Volume attachment id format: %<attach_id> */
        pop_u8(vol);
        u64 attach_id;
        boolean match = parse_int(vol, 10, &attach_id) && (attach_id == v->attach_id);
        vol->start = 0; /* unconsume data consumed when parsing */
        if (match)
            return true;
    }
    if (!buffer_compare_with_sstring(vol, isstring(v->label, v->label_len)))
        return true;
    if (buffer_length(vol) != 2 * UUID_LEN + 4)
        return false;
    const char *b = buffer_ref(vol, 0);
    return (!buf_hex_cmp(v->uuid, b, 4) && (b[8] == '-') &&
            !buf_hex_cmp(v->uuid + 4, b + 9, 2) && (b[13] == '-') &&
            !buf_hex_cmp(v->uuid + 6, b + 14, 2) && (b[18] == '-') &&
            !buf_hex_cmp(v->uuid + 8, b + 19, 2) && (b[23] == '-') &&
            !buf_hex_cmp(v->uuid + 10, b + 24, 6));
}

closure_function(2, 2, void, volume_link,
                 volume, v, inode, mount_dir,
                 filesystem fs, status s)
{
    volume v = bound(v);
    if (is_ok(s)) {
        inode mount_dir = bound(mount_dir);
        int fss = filesystem_mount(storage.root_fs, mount_dir, fs);
        if (fss != 0) {
            msg_err("cannot mount filesystem: %s\n", string_from_errno(-fss));
        } else {
            v->fs = fs;
            v->mount_dir = mount_dir;
            storage_debug("volume mounted, mount directory %p, filesystem %p", mount_dir, fs);
            notify_mount_change_locked();
        }
    } else {
        msg_err("cannot mount filesystem: %v\n", s);
    }
    v->mounting = false;
    if (!v->fs && (fs != INVALID_ADDRESS))
        filesystem_release(fs);
    closure_finish();
    timm_dealloc(s);
    if (!storage.mounting)
        storage_check_if_ready();
}

static void volume_mount(volume v, buffer mount_point)
{
    boolean readonly = false;
    sstring cmount_point = buffer_to_sstring(mount_point);
    int i = buffer_strstr(mount_point, ss(":ro"));
    if (i > 0) {
        cmount_point.len = i;
        readonly = true;
    }
    filesystem fs = storage.root_fs;
    tuple root = filesystem_getroot(storage.root_fs);
    tuple mount_dir_t;
    int fss = filesystem_get_node(&fs, fs->get_inode(fs, root), cmount_point,
        false, false, false, false, &mount_dir_t, 0);
    if (fss != 0) {
        msg_err("mount point %s not found\n", cmount_point);
        return;
    }
    inode mount_dir = fs->get_inode(fs, mount_dir_t);
    boolean ok = (fs == storage.root_fs) && (mount_dir_t != root) && children(mount_dir_t);
    filesystem_put_node(fs, mount_dir_t);
    if (!ok) {
        msg_err("invalid mount point %s\n", cmount_point);
        return;
    }
    filesystem_complete complete = closure(storage.h, volume_link,
        v, mount_dir);
    if (complete == INVALID_ADDRESS) {
        msg_err("cannot allocate closure\n");
        return;
    }
    storage_debug("mounting volume%s at %s", readonly ? ss(" readonly") : sstring_empty(),
                  cmount_point);
    v->mounting = true;
    apply(v->init_handler, readonly, complete);
}

static void storage_io_sg(block_io op, sg_list sg, range blocks, status_handler completion)
{
    merge m = allocate_merge(storage.h, completion);
    completion = apply_merge(m);
    while (range_span(blocks)) {
        sg_buf sgb = sg_list_head_peek(sg);
        u64 length = MIN(sg_buf_len(sgb), range_span(blocks) << SECTOR_OFFSET);
        u64 block_count = length >> SECTOR_OFFSET;
        apply(op, sgb->buf + sgb->offset, irangel(blocks.start, block_count), apply_merge(m));
        sg_consume(sg, length);
        blocks.start += block_count;
    }
    apply(completion, STATUS_OK);
}

define_closure_function(2, 1, void, storage_simple_req_handler,
                        block_io, read, block_io, write,
                        storage_req req)
{
    switch (req->op) {
    case STORAGE_OP_READSG:
        storage_io_sg(bound(read), req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_WRITESG:
        storage_io_sg(bound(write), req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_FLUSH:
        async_apply_status_handler(req->completion, STATUS_OK);
        break;
    case STORAGE_OP_READ:
        apply(bound(read), req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_WRITE:
        apply(bound(write), req->data, req->blocks, req->completion);
        break;
    }
}

storage_req_handler storage_init_req_handler(closure_ref(storage_simple_req_handler, handler),
                                             block_io read, block_io write)
{
    return init_closure(handler, storage_simple_req_handler, read, write);
}

void init_volumes(heap h)
{
    storage.h = h;
    list_init(&storage.volumes);
    storage.root_fs = 0;
    storage.mounts = 0;
    storage.mount_complete = 0;
    spin_lock_init(&storage.lock);
    storage.mount_generation = 0;
    storage.mounts_watchers = allocate_vector(h, 1);
    assert(storage.mounts_watchers != INVALID_ADDRESS);
}

void storage_set_root_fs(filesystem root_fs)
{
    storage.root_fs = root_fs;
    fs_set_path_helper(get_root_fs, storage_get_mountpoint);
}

closure_func_basic(binding_handler, boolean, storage_set_mountpoints_each,
                   value k, value path)
{
    assert(is_symbol(k));
    assert(is_string(path));
    storage_debug("mount point for volume %b at %b", symbol_string(k),
                  path);
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (volume_match(k, v))
            volume_mount(v, path);
    }
    return true;
}

void storage_set_mountpoints(tuple mounts)
{
    storage_lock();
    storage.mounts = mounts;
    storage.mounting = true;
    iterate(mounts, stack_closure_func(binding_handler, storage_set_mountpoints_each));
    storage.mounting = false;
    storage_unlock();
    storage_check_if_ready();
}

closure_function(1, 2, boolean, volume_add_mount_each,
                 volume, v,
                 value k, value path)
{
    assert(is_symbol(k));
    assert(is_string(path));
    if (volume_match(k, bound(v))) {
        volume_mount(bound(v), path);
        return false;
    }
    return true;
}

boolean volume_add(u8 *uuid, char *label, void *priv, fs_init_handler init_handler, int attach_id)
{
    storage_debug("new volume");
    volume v = allocate(storage.h, sizeof(*v));
    if (v == INVALID_ADDRESS)
        return false;
    runtime_memcpy(v->uuid, uuid, UUID_LEN);
    runtime_memcpy(v->label, label, VOLUME_LABEL_MAX_LEN);
    v->label_len = sstring_from_cstring(v->label, VOLUME_LABEL_MAX_LEN).len;
    v->priv = priv;
    v->init_handler = init_handler;
    v->attach_id = attach_id;
    v->mounting = false;
    v->fs = 0;
    v->mount_dir = 0;
    storage_lock();
    list_push_back(&storage.volumes, &v->l);
    if (storage.mounts) {
        storage.mounting = true;
        iterate(storage.mounts, stack_closure(volume_add_mount_each, v));
        storage.mounting = false;
    }
    storage_unlock();
    if (storage.mounts)
        storage_check_if_ready();
    return true;
}

void storage_when_ready(status_handler complete)
{
    storage.mount_complete = complete;
    storage_check_if_ready();
}

void storage_sync(status_handler sh)
{
    storage_debug("sync (%F)", sh);
    merge m = allocate_merge(storage.h, sh);
    status_handler complete = apply_merge(m);
    filesystem_flush(storage.root_fs, apply_merge(m));
    storage_lock();
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (v->fs) {
            storage_debug("syncing mounted filesystem %p", v->fs);
            filesystem_flush(v->fs, apply_merge(m));
        }
    }
    storage_unlock();
    apply(complete, STATUS_OK);
}

filesystem storage_get_fs(tuple root)
{
    filesystem fs;
    storage_lock();
    volume v = storage_get_volume(root);
    if (v)
        fs = v->fs;
    else
        fs = 0;
    storage_unlock();
    return fs;
}

inode storage_get_mountpoint(tuple root, filesystem *fs)
{
    inode mount_dir;
    storage_lock();
    volume v = storage_get_volume(root);
    if (v) {
        mount_dir = v->mount_dir;
        *fs = storage.root_fs;
    } else {
        mount_dir = 0;
    }
    storage_unlock();
    return mount_dir;
}

void storage_iterate(volume_handler vh)
{
    apply(vh, 0, ss("root"), storage.root_fs, 0);
    storage_lock();
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (v->fs)
            apply(vh, v->uuid, isstring(v->label, v->label_len), v->fs, v->mount_dir);
    }
    storage_unlock();
}

void storage_detach(void *priv, thunk complete)
{
    storage_debug("%s", func_ss);
    volume vol = 0;
    storage_lock();
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (v->priv == priv) {
            list_delete(&v->l);
            vol = v;
            notify_mount_change_locked();
            break;
        }
    }
    storage_unlock();
    if (vol) {
        storage_debug("  detaching volume %p, filesystem %p", vol, vol->fs);
        if (vol->fs)
            filesystem_unmount(storage.root_fs, vol->mount_dir, vol->fs, complete);
        else
            apply(complete);
        deallocate(storage.h, vol, sizeof(*vol));
    }
}

void storage_register_mount_notify(mount_notification_handler nh)
{
    storage_lock();
    vector_push(storage.mounts_watchers, nh);
    storage_unlock();
}

void storage_unregister_mount_notify(mount_notification_handler nh)
{
    storage_lock();
    for (int i = 0; i < vector_length(storage.mounts_watchers); i++) {
        if (vector_get(storage.mounts_watchers, i) == nh) {
            vector_delete(storage.mounts_watchers, i);
            break;
        }
    }
    storage_unlock();
}

static void notify_mount_change_locked(void)
{
    mount_notification_handler nh;

    storage.mount_generation++;
    vector_foreach(storage.mounts_watchers, nh)
        apply(nh, storage.mount_generation);
}
