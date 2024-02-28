#include <unix_internal.h>
#include <filesystem.h>
#include <tmpfs.h>

#define MEMFD_KNOWN_FLAGS   \
    (MFD_CLOEXEC | MFD_ALLOW_SEALING)

static struct {
    filesystem fs;
} shmem;

sysreturn memfd_create(const char *name, unsigned int flags)
{
    if (flags & ~MEMFD_KNOWN_FLAGS)
        return -EINVAL;
    return file_open(shmem.fs, shmem.fs->root, O_RDWR | O_TMPFILE, 0);
}

int init(status_handler complete)
{
    shmem.fs = tmpfs_new();
    if (shmem.fs == INVALID_ADDRESS) {
        rprintf("shmem: failed to create tmpfs\n");
        return KLIB_INIT_FAILED;
    }
    swap_syscall_handler(linux_syscalls, SYS_memfd_create, memfd_create);
    return KLIB_INIT_OK;
}
