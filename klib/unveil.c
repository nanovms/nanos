#include <unix_internal.h>
#include <net_system_structs.h>
#include <socket.h>

#include "sandbox.h"

#define UNVEIL_READ     U64_FROM_BIT(0)
#define UNVEIL_WRITE    U64_FROM_BIT(1)
#define UNVEIL_EXEC     U64_FROM_BIT(2)
#define UNVEIL_CREATE   U64_FROM_BIT(3)

#define UNVEIL_PERMS_VALID  U64_FROM_BIT(63)

static struct {
    heap h;
    table dirs;
    struct rw_spinlock lock;
    boolean locked;
} unv;

typedef struct unveil_dir {
    filesystem fs;
    inode ino;
    u64 perms;
    table dir_entries;
} *unveil_dir;

#define unveil_syscall_register_handler(syscalls, call, handler)    \
    vector_push(&(syscalls)[SYS_##call].sb_handlers, unveil_##handler)

#define unveil_syscall_register(syscalls, call) \
    unveil_syscall_register_handler(syscalls, call, call)

/* increments refcount of returned filesystem */
static filesystem get_cwd_fs(int dirfd, const char *path, inode *cwd)
{
    filesystem fs;
    process p = current->p;
    if (*path == '/') {
        fs = p->root_fs;
        filesystem_reserve(fs);
        *cwd = fs->get_inode(fs, filesystem_getroot(fs));
    } else if (dirfd == AT_FDCWD) {
        process_get_cwd(p, &fs, cwd);
    } else {
        fdesc f = fdesc_get(p, dirfd);
        if (!f)
            return 0;
        if (fdesc_type(f) == FDESC_TYPE_DIRECTORY) {
            fs = ((file)f)->fs;
            filesystem_reserve(fs);
            *cwd = ((file)f)->n;
        } else {
            fs = 0;
        }
        fdesc_put(f);
        if (!fs)
            return 0;
    }
    return fs;
}

static key unveil_dir_key(void *a)
{
    return ((unveil_dir)a)->ino;
}

static boolean unveil_dir_equal(void *a, void *b)
{
    return ((unveil_dir)a)->fs == ((unveil_dir)b)->fs;
}

static unveil_dir unveil_new_dir(filesystem fs, tuple md, u64 perms)
{
    unveil_dir dir = allocate(unv.h, sizeof(*dir));
    if (dir == INVALID_ADDRESS)
        return 0;
    dir->fs = fs;
    dir->ino = fs->get_inode(fs, md);
    dir->perms = perms;
    dir->dir_entries = 0;
    table_set(unv.dirs, dir, dir);
    return dir;
}

static unveil_dir unveil_find_dir(filesystem fs, tuple md)
{
    struct unveil_dir d = {
        .fs = fs,
        .ino = fs->get_inode(fs, md),
    };
    return table_find(unv.dirs, &d);
}

static sysreturn unveil_set_dir_perms(filesystem fs, tuple md, u64 perms)
{
    unveil_dir dir = unveil_find_dir(fs, md);
    if (!dir) {
        dir = unveil_new_dir(fs, md, 0);
        if (!dir)
            return -ENOMEM;
    }
    u64 old_perms = dir->perms;
    if ((old_perms & UNVEIL_PERMS_VALID) && (perms & ~old_perms))
        return -EPERM;
    dir->perms = perms;
    return 0;
}

static sysreturn unveil_set_dir_entry_perms(filesystem fs, tuple md, symbol name, u64 perms)
{
    unveil_dir dir = unveil_find_dir(fs, md);
    if (!dir) {
        dir = unveil_new_dir(fs, md, 0);
        if (!dir)
            return -ENOMEM;
    }
    if (!dir->dir_entries) {
        table entries = allocate_table(unv.h, key_from_symbol, pointer_equal);
        if (entries == INVALID_ADDRESS)
            return -ENOMEM;
        dir->dir_entries = entries;
    }
    u64 old_perms = u64_from_pointer(table_find(dir->dir_entries, name));
    if ((old_perms & UNVEIL_PERMS_VALID) && (perms & ~old_perms))
        return -EPERM;
    table_set(dir->dir_entries, name, pointer_from_u64(perms));
    return 0;
}

static sysreturn unveil(const char *path, const char *permissions)
{
    if (!path && !permissions) {
        unv.locked = true;
        return 0;
    }
    if (unv.locked)
        return -EPERM;
    sstring path_ss, permissions_ss;
    if (!fault_in_user_string(path, &path_ss) ||
        !fault_in_user_string(permissions, &permissions_ss))
        return -EFAULT;
    u64 perms = UNVEIL_PERMS_VALID;
    sstring_foreach(i, p, permissions_ss) {
        switch (p) {
        case 'r':
            perms |= UNVEIL_READ;
            break;
        case 'w':
            perms |= UNVEIL_WRITE;
            break;
        case 'x':
            perms |= UNVEIL_EXEC;
            break;
        case 'c':
            perms |= UNVEIL_CREATE;
            break;
        default:
            return -EINVAL;
        }
    }
    sysreturn rv = 0;
    spin_wlock(&unv.lock);
    if (!unv.dirs) {
        table dirs = allocate_table(unv.h, unveil_dir_key, unveil_dir_equal);
        if (dirs != INVALID_ADDRESS) {
            unv.dirs = dirs;
        } else {
            rv = -ENOMEM;
            goto unlock;
        }
    }
    filesystem fs, cwd_fs;
    inode cwd;
    tuple n;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    fs = cwd_fs;
    if (filesystem_get_node(&fs, cwd, path_ss, false, false, false, false, &n, 0) == FS_STATUS_OK) {
        if (is_dir(n)) {
            rv = unveil_set_dir_perms(fs, n, perms);
        } else {
            tuple parent = get_tuple(n, sym_this(".."));
            rv = unveil_set_dir_entry_perms(fs, parent, tuple_get_symbol(children(parent), n),
                                            perms);
        }
        filesystem_put_node(fs, n);
    } else {
        /* Unveiling a nonexistent path: if the parent directory exists, set unveil permissions for
         * the given file name in the parent directory. */
        bytes path_len = path_ss.len;
        char *dir_separator = path_find_last_delim(path_ss);
        sstring parent_path;
        if (dir_separator) {
            if (dir_separator - path == path_len - 1) {
                rv = -ENOENT;
                goto release;
            }
            parent_path.ptr = path_ss.ptr;
            parent_path.len = dir_separator - path + 1; /* include final '/' */
        } else {
            parent_path = ss(".");
        }
        if (filesystem_get_node(&fs, cwd, parent_path, false, false, false, false, &n, 0) ==
            FS_STATUS_OK) {
            sstring dir_entry;
            if (dir_separator) {
                dir_entry.ptr = dir_separator + 1;
                dir_entry.len = path_ss.len - parent_path.len;
            } else {
                dir_entry = path_ss;
            }
            rv = unveil_set_dir_entry_perms(fs, n, sym_sstring(dir_entry), perms);
            filesystem_put_node(fs, n);
        } else {
            rv = -ENOENT;
        }
    }
  release:
    filesystem_release(cwd_fs);
  unlock:
    spin_wunlock(&unv.lock);
    return rv;
}

/* Given a filesystem node, retrieves its permissions by traversing the node path up to the root
 * node, until an unveil entry is found. */
static u64 unveil_get_perms(filesystem fs, tuple md)
{
    spin_rlock(&unv.lock);
    unveil_dir dir = unveil_find_dir(fs, md);
    u64 perms = 0;
    if (dir)
        perms = dir->perms;
    while (!(perms & UNVEIL_PERMS_VALID)) {
        tuple parent = get_tuple(md, sym_this(".."));
        if (parent == md)
            break;
        dir = unveil_find_dir(fs, parent);
        if (dir) {
            if (dir->dir_entries) {
                symbol name = tuple_get_symbol(children(parent), md);
                perms = u64_from_pointer(table_find(dir->dir_entries, name));
            }
            if (!(perms & UNVEIL_PERMS_VALID))
                perms = dir->perms;
        }
        md = parent;
    }
    spin_runlock(&unv.lock);
    return perms;
}

static sysreturn unveil_check_path_internal(filesystem fs, inode cwd, sstring path, boolean nofollow,
                                            u64 perms)
{
    tuple n;
    fs_status fss = filesystem_get_node(&fs, cwd, path, nofollow,
                                        false, false, false, &n, 0);
    u64 unveil_perms = 0;
    if (fss == FS_STATUS_OK) {
        do {
            unveil_perms = unveil_get_perms(fs, n);
            if ((unveil_perms & UNVEIL_PERMS_VALID) || (n == filesystem_getroot(fs))) {
                filesystem_put_node(fs, n);
                break;
            }
            inode ino = fs->get_inode(fs, n);
            filesystem_put_node(fs, n);
            fss = filesystem_get_node(&fs, ino, ss(".."), true, false, false, false, &n, 0);
        } while (fss == FS_STATUS_OK);
    } else {
        /* Nonexistent path: look for the parent directory. */
        char *dir_separator = path_find_last_delim(path);
        sstring parent_path;
        if (dir_separator) {
            if (dir_separator != path.ptr) {
                parent_path.ptr = path.ptr;
                parent_path.len = dir_separator - path.ptr;
            } else {
                parent_path = ss("/");
            }
        } else {
            parent_path = ss(".");
        }
        fss = filesystem_get_node(&fs, cwd, parent_path, false, false, false, false, &n, 0);
        if (fss == FS_STATUS_OK) {
            unveil_dir dir = unveil_find_dir(fs, n);
            if (dir && dir->dir_entries) {
                sstring dir_entry;
                if (dir_separator) {
                    dir_entry.ptr = dir_separator + 1;
                    dir_entry.len = path.len - (dir_separator + 1 - path.ptr);
                } else {
                    dir_entry = path;
                }
                unveil_perms = u64_from_pointer(table_find(dir->dir_entries,
                                                           sym_sstring(dir_entry)));
            }
            filesystem_put_node(fs, n);
        }
        if (!(unveil_perms & UNVEIL_PERMS_VALID)) {
            if (dir_separator) {
                path.len = dir_separator - path.ptr;
                return unveil_check_path_internal(fs, cwd, path, false, perms);
            } else {
                tuple md = filesystem_get_meta(fs, cwd);
                if (md) {
                    unveil_perms = unveil_get_perms(fs, md);
                    filesystem_put_meta(fs, md);
                }
            }
        }
    }
    if (!(unveil_perms & UNVEIL_PERMS_VALID))
        return -ENOENT;
    return (perms & ~unveil_perms) ? -EACCES : 0;
}

static boolean unveil_check_path_at(int dirfd, const char *path, boolean nofollow, u64 perms,
                                    sysreturn *rv)
{
    sstring path_ss;
    if (!unv.dirs || !fault_in_user_string(path, &path_ss))
        return false;
    inode cwd;
    filesystem fs = get_cwd_fs(dirfd, path, &cwd);
    if (!fs)
        return false;
    sysreturn ret = unveil_check_path_internal(fs, cwd, path_ss, nofollow, perms);
    filesystem_release(fs);
    if (!ret)
        return false;
    *rv = ret;
    return true;
}

static boolean unveil_check_path(const char *path, boolean nofollow, u64 perms, sysreturn *rv)
{
    return unveil_check_path_at(AT_FDCWD, path, nofollow, perms, rv);
}

static boolean unveil_bind(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                           sysreturn *rv)
{
    fdesc f = fdesc_get(current->p, arg0);
    boolean result = false;
    if (!f)
        return result;
    struct sockaddr_un *addr = (struct sockaddr_un *)arg1;
    socklen_t addrlen = arg2;
    if ((f->type == FDESC_TYPE_SOCKET) && (((struct sock *)f)->domain == AF_UNIX) &&
        (addrlen > offsetof(struct sockaddr_un *, sun_path)) &&
        validate_user_memory(addr, addrlen, false))
        result = unveil_check_path(addr->sun_path, false, UNVEIL_CREATE, rv);
    fdesc_put(f);
    return result;
}

static boolean unveil_truncate(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_WRITE, rv);
}

static boolean unveil_chdir(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_READ, rv);
}

static boolean unveil_statfs(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_READ, rv);
}

static boolean unveil_acct(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                           sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_WRITE, rv);
}

static boolean unveil_mount(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    return unveil_check_path((const char *)arg1, false, UNVEIL_READ, rv);
}

static boolean unveil_umount2(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                              sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_READ, rv);
}

static boolean unveil_swapon(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_READ | UNVEIL_WRITE, rv);
}

static boolean unveil_swapoff(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                              sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_READ, rv);
}

static boolean unveil_setxattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_WRITE, rv);
}

static boolean unveil_lsetxattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, true, UNVEIL_WRITE, rv);
}

static boolean unveil_getxattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_READ, rv);
}

static boolean unveil_lgetxattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, true, UNVEIL_READ, rv);
}

static boolean unveil_listxattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_READ, rv);
}

static boolean unveil_llistxattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                 sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, true, UNVEIL_READ, rv);
}

static boolean unveil_removexattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                  sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, false, UNVEIL_WRITE, rv);
}

static boolean unveil_lremovexattr(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                   sysreturn *rv)
{
    return unveil_check_path((const char *)arg0, true, UNVEIL_WRITE, rv);
}

static boolean unveil_inotify_add_watch(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                        sysreturn *rv)
{
    return unveil_check_path((const char *)arg1, !!(arg2 & IN_DONT_FOLLOW), UNVEIL_READ, rv);
}

static boolean unveil_openat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    int flags = arg2;
    u64 perms;
    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        perms = UNVEIL_READ;
        break;
    case O_WRONLY:
        perms = UNVEIL_WRITE;
        break;
    case O_RDWR:
        perms = UNVEIL_READ | UNVEIL_WRITE;
        break;
    default:
        perms = 0;
    }
    if (flags & O_TRUNC)
        perms |= UNVEIL_WRITE;
    if (flags & O_CREAT)
        perms |= UNVEIL_CREATE;
    return unveil_check_path_at(arg0, (const char *)arg1, !!(flags & O_NOFOLLOW), perms, rv);
}

static boolean unveil_createat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    return unveil_check_path_at(arg0, (const char *)arg1, true, UNVEIL_CREATE, rv);
}

static boolean unveil_newfstatat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                 sysreturn *rv)
{
    return unveil_check_path_at(arg0, (const char *)arg1, !!(arg3 & AT_SYMLINK_NOFOLLOW),
                                UNVEIL_READ, rv);
}

static boolean unveil_unlinkat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    const char *path = (const char *)arg1;
    if (unveil_check_path_at(arg0, path, true, UNVEIL_CREATE, rv))
        return true;
    sstring path_ss;
    if ((arg2 & AT_REMOVEDIR) && unv.dirs && fault_in_user_string(path, &path_ss)) {
        /* If the directory being removed has an unveil entry, remove the unveil entry. */
        inode cwd;
        filesystem cwd_fs = get_cwd_fs(arg0, path, &cwd);
        if (!cwd_fs)
            return false;
        filesystem fs = cwd_fs;
        tuple n;
        fs_status fss = filesystem_get_node(&fs, cwd, path_ss, true, false, false, false, &n, 0);
        if (fss == FS_STATUS_OK) {
            struct unveil_dir d = {
                .fs = fs,
                .ino = fs->get_inode(fs, n),
            };
            spin_wlock(&unv.lock);
            unveil_dir dir = table_remove(unv.dirs, &d);
            spin_wunlock(&unv.lock);
            if (dir) {
                if (dir->dir_entries)
                    deallocate_table(dir->dir_entries);
                deallocate(unv.h, dir, sizeof(*dir));
            }
            filesystem_put_node(fs, n);
        }
        filesystem_release(cwd_fs);
    }
    return false;
}

static boolean unveil_renameat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return unveil_check_path_at(arg0, (const char *)arg1, true, UNVEIL_CREATE, rv) ||
           unveil_check_path_at(arg2, (const char *)arg3, true, UNVEIL_CREATE, rv);
}

static boolean unveil_linkat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_check_path_at(arg2, (const char *)arg3, true, UNVEIL_CREATE, rv);
}

static boolean unveil_symlinkat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return unveil_check_path_at(arg1, (const char *)arg2, true, UNVEIL_CREATE, rv);
}

static boolean unveil_readlinkat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                 sysreturn *rv)
{
    return unveil_check_path_at(arg0, (const char *)arg1, true, UNVEIL_READ, rv);
}

static boolean unveil_faccessat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    int mode = arg2;
    u64 perms = 0;
    if (mode != F_OK) {
        if (mode & R_OK)
            perms |= UNVEIL_READ;
        if (mode & W_OK)
            perms |= UNVEIL_WRITE;
    }
    return unveil_check_path_at(arg0, (const char *)arg1, !!(arg3 & AT_SYMLINK_NOFOLLOW),
                                perms, rv);
}

#ifdef __x86_64__

static boolean unveil_open(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                           sysreturn *rv)
{
    return unveil_openat(AT_FDCWD, arg0, arg1, arg2, 0, 0, rv);
}

static boolean unveil_stat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                           sysreturn *rv)
{
    return unveil_newfstatat(AT_FDCWD, arg0, arg1, 0, 0, 0, rv);
}

static boolean unveil_lstat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    return unveil_newfstatat(AT_FDCWD, arg0, arg1, AT_SYMLINK_NOFOLLOW, 0, 0, rv);
}

static boolean unveil_access(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_faccessat(AT_FDCWD, arg0, arg1, 0, 0, 0, rv);
}

static boolean unveil_rename(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_renameat(AT_FDCWD, arg0, AT_FDCWD, arg1, 0, 0, rv);
}

static boolean unveil_rmdir(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    return unveil_unlinkat(AT_FDCWD, arg0, AT_REMOVEDIR, 0, 0, 0, rv);
}

static boolean unveil_create(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_createat(AT_FDCWD, arg0, 0, 0, 0, 0, rv);
}

static boolean unveil_creat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    return unveil_open(arg0, O_CREAT | O_WRONLY | O_TRUNC, arg1, 0, 0, 0, rv);
}

static boolean unveil_symlink(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                              sysreturn *rv)
{
    return unveil_symlinkat(arg0, AT_FDCWD, arg1, 0, 0, 0, rv);
}

static boolean unveil_readlink(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    return unveil_readlinkat(AT_FDCWD, arg0, 0, 0, 0, 0, rv);
}

static boolean unveil_uselib(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_open(arg0, O_RDONLY, 0, 0, 0, 0, rv);
}

static boolean unveil_utimes(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return unveil_open(arg0, O_WRONLY, 0, 0, 0, 0, rv);
}

static boolean unveil_futimesat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return unveil_openat(arg0, arg1, O_WRONLY, 0, 0, 0, rv);
}

#endif

boolean unveil_init(sb_syscall syscalls, tuple cfg)
{
    unv.h = heap_locked(get_kernel_heaps());
    spin_rw_lock_init(&unv.lock);
    register_syscall(linux_syscalls, unveil, unveil, 0);
    unveil_syscall_register(syscalls, bind);
    unveil_syscall_register(syscalls, truncate);
    unveil_syscall_register(syscalls, chdir);
    unveil_syscall_register(syscalls, statfs);
    unveil_syscall_register(syscalls, acct);
    unveil_syscall_register(syscalls, mount);
    unveil_syscall_register(syscalls, umount2);
    unveil_syscall_register(syscalls, swapon);
    unveil_syscall_register(syscalls, swapoff);
    unveil_syscall_register(syscalls, setxattr);
    unveil_syscall_register(syscalls, lsetxattr);
    unveil_syscall_register(syscalls, getxattr);
    unveil_syscall_register(syscalls, lgetxattr);
    unveil_syscall_register(syscalls, listxattr);
    unveil_syscall_register(syscalls, llistxattr);
    unveil_syscall_register(syscalls, removexattr);
    unveil_syscall_register(syscalls, lremovexattr);
    unveil_syscall_register(syscalls, inotify_add_watch);
    unveil_syscall_register(syscalls, openat);
    unveil_syscall_register_handler(syscalls, mkdirat, createat);
    unveil_syscall_register_handler(syscalls, mknodat, createat);
    unveil_syscall_register(syscalls, newfstatat);
    unveil_syscall_register(syscalls, unlinkat);
    unveil_syscall_register(syscalls, renameat);
    unveil_syscall_register(syscalls, linkat);
    unveil_syscall_register(syscalls, symlinkat);
    unveil_syscall_register(syscalls, readlinkat);
    unveil_syscall_register(syscalls, faccessat);
#ifdef __x86_64__
    unveil_syscall_register(syscalls, open);
    unveil_syscall_register(syscalls, stat);
    unveil_syscall_register(syscalls, lstat);
    unveil_syscall_register(syscalls, access);
    unveil_syscall_register(syscalls, rename);
    unveil_syscall_register_handler(syscalls, mkdir, create);
    unveil_syscall_register(syscalls, rmdir);
    unveil_syscall_register(syscalls, creat);
    unveil_syscall_register_handler(syscalls, unlink, create);
    unveil_syscall_register(syscalls, symlink);
    unveil_syscall_register(syscalls, readlink);
    unveil_syscall_register_handler(syscalls, mknod, create);
    unveil_syscall_register(syscalls, uselib);
    unveil_syscall_register(syscalls, utimes);
    unveil_syscall_register(syscalls, futimesat);
#endif
    unveil_syscall_register_handler(syscalls, renameat2, renameat);
    return true;
}
