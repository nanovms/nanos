#include <kernel.h>
#include <pagecache.h>
#include <storage.h>
#include <tfs.h>
#include <unix.h>

typedef struct volume {
    struct list l;
    u8 uuid[UUID_LEN];
    block_io r, w;
    u64 size;
    boolean mounting;
    filesystem fs;
    tuple mount_dir;
} *volume;

static struct {
    heap h;
    filesystem root_fs;
    struct list volumes;
    tuple mounts;
    thunk mount_complete;
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
    thunk complete = 0;
    storage_lock();
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
        apply(complete);
}

static boolean volume_match(symbol s, volume v)
{
    /* UUID format in symbol string: 00112233-4455-6677-8899-aabbccddeeff */
    buffer vol = symbol_string(s);
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
                 volume, v, tuple, mount_dir,
                 filesystem, fs, status, s)
{
    volume v = bound(v);
    if (is_ok(s)) {
        tuple mount_dir = bound(mount_dir);
        tuple volume_root = filesystem_getroot(fs);
        tuple mount = allocate_tuple();
        table_set(mount, sym(root), volume_root);
        table_set(mount, sym(no_encode), null_value); /* non-persistent entry */
        table_set(mount_dir, sym(mount), mount);
        v->fs = fs;
        v->mount_dir = mount_dir;
        storage_debug("volume mounted, mount directory %p, root %p", mount_dir,
                      volume_root);
    } else {
        msg_err("cannot mount filesystem: %v\n", s);
    }
    v->mounting = false;
    closure_finish();
    timm_dealloc(s);
    storage_check_if_ready();
}

static void volume_mount(volume v, buffer mount_point)
{
    tuple root = filesystem_getroot(storage.root_fs);
    vector path = split(storage.h, mount_point, '/');
    tuple mount_dir = resolve_path(root, path);
    deallocate_vector(path);
    if (!mount_dir || (mount_dir == root) || !children(mount_dir)) {
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
    create_filesystem(storage.h, SECTOR_SIZE, v->size, v->r, v->w, false,
                      complete);
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
}

void storage_set_mountpoints(tuple mounts)
{
    storage_lock();
    storage.mounts = mounts;
    table_foreach(mounts, k, path) {
        storage_debug("mount point for volume %b at %b", symbol_string(k),
            path);
        list_foreach(&storage.volumes, e) {
            volume v = struct_from_list(e, volume, l);
            if (volume_match(k, v))
                volume_mount(v, path);
        }
    }
    storage_unlock();
}

boolean volume_add(u8 *uuid, block_io r, block_io w, u64 size)
{
    storage_debug("new volume (%ld bytes)", size);
    volume v = allocate(storage.h, sizeof(*v));
    if (v == INVALID_ADDRESS)
        return false;
    runtime_memcpy(v->uuid, uuid, UUID_LEN);
    v->r = r;
    v->w = w;
    v->size = size;
    v->mounting = false;
    v->fs = 0;
    v->mount_dir = 0;
    storage_lock();
    list_push_back(&storage.volumes, &v->l);
    if (storage.mounts)
        table_foreach(storage.mounts, k, path) {
            if (volume_match(k, v)) {
                volume_mount(v, path);
                break;
            }
        }
    storage_unlock();
    return true;
}

void storage_when_ready(thunk complete)
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

tuple storage_get_mountpoint(tuple root)
{
    tuple mount_dir;
    storage_lock();
    volume v = storage_get_volume(root);
    if (v)
        mount_dir = v->mount_dir;
    else
        mount_dir = 0;
    storage_unlock();
    return mount_dir;
}
