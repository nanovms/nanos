#include <kernel.h>
#include <pagecache.h>
#include <storage.h>
#include <tfs.h>
#include <unix.h>

typedef struct volume {
    struct list l;
    u8 uuid[UUID_LEN];
    char label[VOLUME_LABEL_MAX_LEN];
    block_io r, w;
    block_flush flush;
    u64 size;
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
} storage;

//#define STORAGE_DEBUG
#ifdef STORAGE_DEBUG
#define storage_debug(x, ...) do {  \
    rprintf("STORAGE: " x "\n", ##__VA_ARGS__); \
} while(0)
#else
#define storage_debug(x, ...)
#endif

#define storage_lock()      u64 _irqflags = spin_lock_irq(&storage.lock)
#define storage_unlock()    spin_unlock_irq(&storage.lock, _irqflags)

/* Called with mutex locked. */
// XXX this won't work with wrapped root...
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
    if (buffer_compare_with_cstring(vol, v->label))
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
                 filesystem, fs, status, s)
{
    volume v = bound(v);
    if (is_ok(s)) {
        inode mount_dir = bound(mount_dir);
        fs_status fss = filesystem_mount(storage.root_fs, mount_dir, fs);
        if (fss != FS_STATUS_OK) {
            msg_err("cannot mount filesystem: %s\n", string_from_fs_status(fss));
        } else {
            v->fs = fs;
            v->mount_dir = mount_dir;
            storage_debug("volume mounted, mount directory %p, filesystem %p", mount_dir, fs);
        }
    } else {
        msg_err("cannot mount filesystem: %v\n", s);
    }
    v->mounting = false;
    closure_finish();
    timm_dealloc(s);
    if (!storage.mounting)
        storage_check_if_ready();
}

static void volume_mount(volume v, buffer mount_point)
{
    filesystem fs = storage.root_fs;
    tuple root = filesystem_getroot(storage.root_fs);
    tuple mount_dir_t;
    fs_status fss = filesystem_get_node(&fs, inode_from_tuple(root), buffer_to_cstring(mount_point),
        false, false, false, &mount_dir_t, 0);
    if (fss != FS_STATUS_OK) {
        msg_err("mount point %b not found\n", mount_point);
        return;
    }
    inode mount_dir = inode_from_tuple(mount_dir_t);
    boolean ok = (fs == storage.root_fs) && (mount_dir_t != root) && children(mount_dir_t);
    filesystem_put_node(fs, mount_dir_t);
    if (!ok) {
        msg_err("invalid mount point %b\n", mount_point);
        return;
    }
    filesystem_complete complete = closure(storage.h, volume_link,
        v, mount_dir);
    if (complete == INVALID_ADDRESS) {
        msg_err("cannot allocate closure\n");
        return;
    }
    storage_debug("mounting volume at %b", mount_point);
    v->mounting = true;
    create_filesystem(storage.h, SECTOR_SIZE, v->size, v->r, v->w, v->flush,
                      0 /* no label */, complete);
}

void init_volumes(heap h)
{
    storage.h = h;
    list_init(&storage.volumes);
    storage.root_fs = 0;
    storage.mounts = 0;
    storage.mount_complete = 0;
    spin_lock_init(&storage.lock);
}

void storage_set_root_fs(filesystem root_fs)
{
    storage.root_fs = root_fs;
    fs_set_path_helper(get_root_fs, storage_get_mountpoint);
}

closure_function(0, 2, boolean, storage_set_mountpoints_each,
                 value, k, value, path)
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
    iterate(mounts, stack_closure(storage_set_mountpoints_each));
    storage.mounting = false;
    storage_unlock();
    storage_check_if_ready();
}

closure_function(1, 2, boolean, volume_add_mount_each,
                 volume, v,
                 value, k, value, path)
{
    assert(is_symbol(k));
    assert(is_string(path));
    if (volume_match(k, bound(v))) {
        volume_mount(bound(v), path);
        return false;
    }
    return true;
}

boolean volume_add(u8 *uuid, char *label, block_io r, block_io w, block_flush flush, u64 size)
{
    storage_debug("new volume (%ld bytes)", size);
    volume v = allocate(storage.h, sizeof(*v));
    if (v == INVALID_ADDRESS)
        return false;
    runtime_memcpy(v->uuid, uuid, UUID_LEN);
    runtime_memcpy(v->label, label, VOLUME_LABEL_MAX_LEN);
    v->r = r;
    v->w = w;
    v->flush = flush;
    v->size = size;
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
    filesystem_sync(storage.root_fs, apply_merge(m));
    storage_lock();
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (v->fs) {
            storage_debug("syncing mounted filesystem %p", v->fs);
            filesystem_sync(v->fs, apply_merge(m));
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
    apply(vh, 0, "root", storage.root_fs, 0);
    storage_lock();
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if (v->fs)
            apply(vh, v->uuid, v->label, v->fs, v->mount_dir);
    }
    storage_unlock();
}
KLIB_EXPORT(storage_iterate);

void storage_detach(block_io r, block_io w, thunk complete)
{
    storage_debug("%s", __func__);
    volume vol = 0;
    storage_lock();
    list_foreach(&storage.volumes, e) {
        volume v = struct_from_list(e, volume, l);
        if ((v->r == r) && (v->w == w)) {
            list_delete(&v->l);
            vol = v;
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
