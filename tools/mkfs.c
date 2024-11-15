#include <runtime.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <storage.h>
#include <tfs.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>

#include <kernel/region.h>

#define string_ends_with(str, substr) ({                \
    int slen = strlen(str);                             \
    int sslen = strlen(substr);                         \
    boolean res;                                        \
    if (slen >= sslen)                                  \
        res = !strcmp((str) + slen - sslen, (substr));  \
    else                                                \
        res = false;                                    \
    res;                                                \
})

/* Must be large enough to contain the minimum number of clusters (64K) for a
 * 32-bit File Allocation Table. */
#define UEFI_PART_SIZE  (33 * MB)

/* Volume Boot Record */
static u8 uefi_part_blob1[] = {
    0xEB, 0x58, 0x90, 0x6D, 0x6B, 0x66, 0x73, 0x2E, 0x66, 0x61, 0x74, 0x00, 0x02, 0x01, 0x20, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x20, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xCC, 0x06, 0x01, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x29, 0x9E, 0xF9, 0x43, 0xDF, 0x4E, 0x4F, 0x20, 0x4E, 0x41, 0x4D, 0x45, 0x20, 0x20,
    0x20, 0x20, 0x46, 0x41, 0x54, 0x33, 0x32, 0x20, 0x20, 0x20, 0x0E, 0x1F, 0xBE, 0x77, 0x7C, 0xAC,
    0x22, 0xC0, 0x74, 0x0B, 0x56, 0xB4, 0x0E, 0xBB, 0x07, 0x00, 0xCD, 0x10, 0x5E, 0xEB, 0xF0, 0x32,
    0xE4, 0xCD, 0x16, 0xCD, 0x19, 0xEB, 0xFE, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6E,
    0x6F, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6F, 0x6F, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x20, 0x64, 0x69,
    0x73, 0x6B, 0x2E, 0x20, 0x20, 0x50, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x20, 0x69, 0x6E, 0x73, 0x65,
    0x72, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6F, 0x6F, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x20, 0x66, 0x6C,
    0x6F, 0x70, 0x70, 0x79, 0x20, 0x61, 0x6E, 0x64, 0x0D, 0x0A, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20,
    0x61, 0x6E, 0x79, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x74, 0x6F, 0x20, 0x74, 0x72, 0x79, 0x20, 0x61,
    0x67, 0x61, 0x69, 0x6E, 0x20, 0x2E, 0x2E, 0x2E, 0x20, 0x0D, 0x0A
};

/* FSInfo Structure */
static u8 uefi_part_blob2[] = {
    0x52, 0x52, 0x61, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x72, 0x72, 0x41, 0x61, 0xAE, 0x01, 0x01, 0x00, 0xF3
};

/* First entries of File Allocation Table */
static u8 uefi_part_blob3[] = {
    0xF8, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0x0F, 0xF8, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0x0F,
    0xFF, 0xFF, 0xFF, 0x0F
};

/* "EFI" entry in root directory */
static u8 uefi_dir_efi[] = {
    0x45, 0x46, 0x49, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x60, 0x39,
    0x7C, 0x52, 0x7C, 0x52, 0x00, 0x00, 0x60, 0x39, 0x7C, 0x52, 0x03
};

/* "EFI" directory entries with "Boot" subfolder */
static u8 uefi_dir_boot[] = {
    0x2E, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2E, 0x2E, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x42, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x00, 0x00, 0x0F, 0x00, 0xDD, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0x42, 0x4F, 0x4F, 0x54, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x04
};

/* "EFI/Boot" directory entries with "bootx64.efi" file */
static u8 uefi_file_bootx64[] = {
    0x2E, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2E, 0x2E, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x62, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x78, 0x00, 0x0F, 0x00, 0x1D, 0x36, 0x00,
    0x34, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x66, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
    0x42, 0x4F, 0x4F, 0x54, 0x58, 0x36, 0x34, 0x20, 0x45, 0x46, 0x49, 0x20, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x05, 0x00
};

/* "EFI/Boot" directory entries with "bootaa64.efi" file */
static u8 uefi_file_bootaa64[] = {
    0x2E, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2E, 0x2E, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x00, 0x00, 0x8F, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x8F, 0x9C, 0x7B, 0x52, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x62, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x61, 0x00, 0x0F, 0x00, 0x54, 0x61, 0x00,
    0x36, 0x00, 0x34, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x66, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00,
    0x42, 0x4F, 0x4F, 0x54, 0x41, 0x41, 0x36, 0x34, 0x45, 0x46, 0x49, 0x20, 0x00, 0x64, 0x4B, 0x9C,
    0x7B, 0x52, 0x7B, 0x52, 0x00, 0x00, 0x4B, 0x9C, 0x7B, 0x52, 0x05, 0x00
};

static buffer read_stdin(heap h)
{
    buffer in = allocate_buffer(h, 1024);
    int r, k;
    while ((r = in->length - in->end) &&
           ((k = read(0, in->contents + in->end, r)), in->end += k, k > 0))
        buffer_extend(in, 1024);
    return in;
}

/**
 * Try to lookup file in target_root
 *
 * Always fills in "st", even if target_root is not specified
 */
buffer lookup_file(heap h, const char *target_root, buffer name, struct stat *st)
{
    buffer target_name = NULL;
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);

    // try target_root
    if (target_root != NULL) {
        char path_buf[PATH_MAX];
        const char *n = buffer_ref(name, 0);
        int len = buffer_length(name);

        target_name = allocate_buffer(h, PATH_MAX);
        while (1) {
            // compose target_name
            buffer_clear(target_name);
            assert(buffer_write(target_name, target_root, strlen(target_root)));
            if (n[0] != '/')
                buffer_write_byte(target_name, '/');
            assert(buffer_write(target_name, n, len));

            if (lstat(cstring(target_name, tmpbuf), st) < 0) {
                if (errno != ENOENT)
                    halt("couldn't stat file %b: %s\n", target_name, errno_sstring());

                // not found in target root -- fallback to lookup on host
                deallocate_buffer(target_name);
                target_name = NULL;
                break;
            }
            if (!S_ISLNK(st->st_mode)) {
                // not a symlink found in target root
                return target_name;
            }

            if ((len = readlink(cstring(target_name, tmpbuf), path_buf, sizeof(path_buf))) < 0)
                halt("couldn't readlink file %b: %s\n", name, errno_sstring());
            if (path_buf[0] != '/') {
                // relative symlinks are ok
                name = target_name;
                break;
            }

            // absolute symlinks need to be resolved again
            n = path_buf;
        }
    }

    if (stat(cstring(name, tmpbuf), st) < 0)
        halt("couldn't stat file %b: %s\n", name, errno_sstring());
    return target_name;
}

// its nice that we can append a file to any existing buffer, but harsh we have to grow the buffer
void read_file(heap h, const char *target_root, buffer dest, buffer name)
{
    // mode bit metadata
    struct stat st;
    buffer target_name = lookup_file(h, target_root, name, &st);
    if (target_name != NULL) {
        //printf("%s -> %s\n", cstring(name), cstring(target_name));
        name = target_name;
    }

    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    int fd = open(cstring(name, tmpbuf), O_RDONLY);
    if (fd < 0) halt("couldn't open file %b: %s\n", name, errno_sstring());
    u64 size = st.st_size;
    buffer_extend(dest, pad(st.st_size, SECTOR_SIZE));
    u64 total = 0;
    while (total < size) {
        int rv = read(fd, buffer_ref(dest, total), size - total);
        if (rv < 0 && errno != EINTR) {
            close(fd);
            halt("read: %b: %s\n", name, errno_sstring());
        }
        total += rv;
    }
    dest->end += size;
    close(fd);

    if (target_name != NULL)
        deallocate_buffer(target_name);
}

heap malloc_allocator();

tuple root;
closure_func_basic(parse_finish, void, finish,
                   void *v)
{
    root = v;
}

closure_func_basic(parse_error, void, perr,
                   string s)
{
    msg_err("manifest parse error: %b", s);
    exit(EXIT_FAILURE);
}

closure_function(2, 1, void, bwrite,
                 descriptor, d, ssize_t, offset,
                 storage_req req)
{
    switch (req->op) {
    case STORAGE_OP_WRITESG:
        break;
    case STORAGE_OP_READSG:
        sg_zero_fill(req->data, range_span(req->blocks) << SECTOR_OFFSET);
        /* no break */
    case STORAGE_OP_FLUSH:
        apply(req->completion, STATUS_OK);
        return;
    default:
        halt("%s: invalid storage op %d\n", func_ss, req->op);
    }
    sg_list sg = req->data;
    u64 offset = bound(offset) + (req->blocks.start << SECTOR_OFFSET);
    u64 total = range_span(req->blocks) << SECTOR_OFFSET;
    struct iovec iov[IOV_MAX];
    int iov_count;
    ssize_t xfer;
    lseek(bound(d), offset, SEEK_SET);
    while (total > 0) {
        iov_count = 0;
        xfer = 0;
        sg_list_foreach(sg, sgb) {
            iov[iov_count].iov_base = sgb->buf + sgb->offset;
            iov[iov_count].iov_len = MIN(sg_buf_len(sgb), total - xfer);
            xfer += iov[iov_count].iov_len;
            if ((++iov_count == IOV_MAX) || (xfer == total))
                break;
        }
        xfer = writev(bound(d), iov, iov_count);
        if (xfer < 0 && errno != EINTR) {
            apply(req->completion, timm("result", "write error %s", errno_sstring()));
            return;
        }
        sg_consume(sg, xfer);
        total -= xfer;
    }
    apply(req->completion, STATUS_OK);
}

static buffer get_file_contents(heap h, const char *target_root, value v)
{
    value path = table_find((table)v, sym(host));
    if (path) {
        // seems like it wouldn't be to hard to arrange
        // for this to avoid the staging copy
        buffer dest = allocate_buffer(h, 1024);
        read_file(h, target_root, dest, path);
        return dest;
    }
    return 0;
}

static value translate(heap h, vector worklist,
                       const char *target_root, filesystem fs, value v);

closure_function(5, 2, boolean, translate_each,
                 heap, h, vector, worklist, const char *, target_root, filesystem, fs, tuple, out,
                 value k, value child)
{
    assert(is_symbol(k));
    if (k == sym(contents)) {
        vector_push(bound(worklist), build_vector(bound(h), bound(out), child));
    } else {
        set(bound(out), k, translate(bound(h), bound(worklist), bound(target_root),
                                     bound(fs), child));
    }
    return true;
}

// dont really like the file/tuple duality, but we need to get something running today,
// so push all the bodies onto a worklist
static value translate(heap h, vector worklist,
                       const char *target_root, filesystem fs, value v)
{
    if (is_tuple(v)) {
        tuple out = allocate_tuple();
        iterate((tuple)v, stack_closure(translate_each, h, worklist, target_root, fs, out));
        return out;
    }
    return v;
}

extern heap init_process_runtime();

static io_status_handler mkfs_write_status;
closure_func_basic(io_status_handler, void, mkfs_write_handler,
                   status s, bytes length)
{
    if (!is_ok(s)) {
        msg_err("write failed with %v", s);
        exit(EXIT_FAILURE);
    }
}

closure_function(4, 2, void, fsc,
                 heap, h, descriptor, out, tuple, root, const char *, target_root,
                 filesystem fs, status s)
{
    tuple root = bound(root);
    if (!root)
        exit(EXIT_FAILURE);

    heap h = bound(h);
    vector worklist = allocate_vector(h, 10);
    tuple md = translate(h, worklist, bound(target_root), fs, root);

    buffer b = allocate_buffer(transient, 64);
    u8 uuid[UUID_LEN];
    filesystem_get_uuid(fs, uuid);
    bprintf(b, "UUID: ");
    print_uuid(b, uuid);
    bprintf(b, "\nmetadata\n");
    print_value(b, md, timm("indent", "0"));
    buffer_print(b);
    deallocate_buffer(b);
    rprintf("\n");

    tfs tfs = (struct tfs *)fs;
    filesystem_write_tuple(tfs, md);
    vector i;
    buffer off = 0;
    vector_foreach(worklist, i) {
        tuple f = vector_get(i, 0);
        buffer contents = get_file_contents(h, bound(target_root), vector_get(i, 1));
        if (contents) {
            if (buffer_length(contents) > 0) {
                fsfile fsf = (fsfile)allocate_fsfile(tfs, f);
                filesystem_write_linear(fsf, buffer_ref(contents, 0), irangel(0, buffer_length(contents)),
                                        ignore_io_status);
                deallocate_buffer(contents);
            } else {
                if (!off)
                    off = value_from_u64(0);
                /* make an empty file */
                filesystem_write_eav(tfs, f, sym(extents), allocate_tuple(), false);
                filesystem_write_eav(tfs, f, sym(filelength), off, false);
            }
        }
    }
    filesystem_flush(fs, ignore_status);
    closure_finish();
}

static void write_blob_padded(descriptor out, u8 *blob, size_t len, boolean with_trailer)
{
    assert(write(out, blob, len) == len);
    u8 trailer[] = {0x55, 0xAA};
    size_t padded_len = SECTOR_SIZE - (with_trailer ? sizeof(trailer) : 0);
    if (len <= padded_len) {
        size_t padding_len = padded_len - len;
        if (padding_len > 0) {
            u8 padding[padding_len];
            zero(padding, padding_len);
            assert(write(out, padding, padding_len) == padding_len);
        }
        if (with_trailer)
            assert(write(out, trailer, sizeof(trailer)) == sizeof(trailer));
    }
}

/* Creates the EFI System Partition, i.e. a FAT32 filesystem with the UEFI loader file in the
 * EFI/Boot directory. */
static ssize_t write_uefi_part(descriptor out, ssize_t offset, const char *uefi_loader)
{
    descriptor in = open(uefi_loader, O_RDONLY);
    if (in < 0) {
        halt("couldn't open UEFI loader file %s: %s\n", uefi_loader, errno_sstring());
    }
    assert(lseek(out, offset, SEEK_SET) == offset);
    write_blob_padded(out, uefi_part_blob1, sizeof(uefi_part_blob1), true);
    /* offset 0x200 */
    write_blob_padded(out, uefi_part_blob2, sizeof(uefi_part_blob2), true);
    /* offset 0x400 */
    assert(lseek(out, 4 * SECTOR_SIZE, SEEK_CUR) > 0);
    /* offset 0xC00 */
    write_blob_padded(out, uefi_part_blob1, sizeof(uefi_part_blob1), true);
    /* offset 0xE00 */
    assert(lseek(out, 25 * SECTOR_SIZE, SEEK_CUR) > 0);
    /* offset 0x4000 */
    assert(write(out, uefi_part_blob3, sizeof(uefi_part_blob3)) == sizeof(uefi_part_blob3));
    struct stat st;
    assert(fstat(in, &st) == 0);
    u32 first_cluster = 0x06;
    u32 last_cluster = first_cluster + (pad(st.st_size, SECTOR_SIZE) >> SECTOR_OFFSET);
    u32 n;
    for (n = first_cluster; n <= last_cluster; n++)
        assert(write(out, &n, sizeof(n)) == sizeof(n));
    n = 0x0FFFFFFF; /* end of cluster chain */
    assert(write(out, &n, sizeof(n)) == sizeof(n));
    assert(lseek(out,
        0x81800 - sizeof(uefi_part_blob3) - (last_cluster - first_cluster + 2) * sizeof(n),
        SEEK_CUR) > 0);
    /* offset 0x85800 */
    write_blob_padded(out, uefi_dir_efi, sizeof(uefi_dir_efi), false);
    /* offset 0x85A00 */
    write_blob_padded(out, uefi_dir_boot, sizeof(uefi_dir_boot), false);
    /* offset 0x85C00 */
    if (string_ends_with(uefi_loader, "bootx64.efi"))
        assert(write(out, uefi_file_bootx64, sizeof(uefi_file_bootx64)) ==
                sizeof(uefi_file_bootx64));
    else if (string_ends_with(uefi_loader, "bootaa64.efi"))
        assert(write(out, uefi_file_bootaa64, sizeof(uefi_file_bootaa64)) ==
                sizeof(uefi_file_bootaa64));
    else
        halt("invalid UEFI loader file name\n");
    /* offset 0x85C7C */
    n = st.st_size;
    assert(write(out, &n, sizeof(n)) == sizeof(n));  /* file size */
    /* offset 0x85C80 */
    assert(lseek(out, 0x180, SEEK_CUR) > 0);
    /* offset 0x85E00 */
    char buf[PAGESIZE];
    ssize_t nr;
    while ((nr = read(in, buf, sizeof(buf))) > 0) {
        ssize_t nw;
        while (nr > 0) {
            nw = write(out, buf, nr);
            assert(nw > 0);
            nr -= nw;
        }
    }
    if (nr < 0) {
        halt("couldn't read from UEFI loader file %s: %s\n", uefi_loader, errno_sstring());
    }
    return offset + UEFI_PART_SIZE;
}

static void write_mbr(descriptor f, boolean uefi)
{
    // get resulting size
    off_t total_size = lseek(f, 0, SEEK_END);
    if (total_size < 0)
        halt("could not get image size: %s\n", errno_sstring());
    assert(total_size % SECTOR_SIZE == 0);

    // read MBR
    char buf[SECTOR_SIZE];
    int res = pread(f, buf, sizeof(buf), 0);
    if (res < 0)
        halt("could not read MBR: %s\n", errno_sstring());
    else if (res != sizeof(buf))
        halt("could not read MBR (short read)\n");

    // first MBR partition entry
    struct partition_entry *e = partition_at(buf, 0);
    if (!e)
        halt("invalid MBR signature\n");

    // FS region comes right before MBR partitions (see boot/stage1.s)
    region r = (region) ((char *) e - sizeof(*r));
    if (r->type != REGION_FILESYSTEM)
        halt("invalid boot record (missing filesystem region) \n");
    u64 fs_offset = SECTOR_SIZE + r->length + KLOG_DUMP_SIZE;
    assert(fs_offset % SECTOR_SIZE == 0);
    u64 fs_size;
    int part_num = 0;
    if (uefi) {
        fs_size = UEFI_PART_SIZE;
        partition_write(&e[part_num++], true, 0xEF, fs_offset, fs_size);
        fs_offset += fs_size;
    }
    fs_size = BOOTFS_SIZE;
    partition_write(&e[part_num++], true, 0x83, fs_offset, fs_size);

    /* Root filesystem */
    fs_offset += fs_size;
    assert(total_size > fs_offset);
    partition_write(&e[part_num++], true, 0x83, fs_offset,
                    total_size - fs_offset);

    // write MBR
    res = pwrite(f, buf, sizeof(buf), 0);
    if (res < 0)
        halt("could not write MBR: %s\n", errno_sstring());
    else if (res != sizeof(buf))
        halt("could not write MBR (short write)\n");
}

static void usage(const char *program_name)
{
    const char *p = strrchr(program_name, '/');
    p = p != NULL ? p + 1 : program_name;
    printf("Usage:\n%s [options] image-file < manifest-file\n"
           "%s [options] -e image-file\n"
           "Options:\n"
           "-b boot-image	- specify boot image to prepend\n"
           "-u uefi-loader	- specify UEFI loader (creates EFI System Partition)\n"
           "-k kern-image	- specify kernel image\n"
           "-l label	- specify filesystem label\n"
           "-r target-root	- specify target root\n"
           "-s image-size	- specify minimum image file size; can be expressed"
           " in bytes, KB (with k or K suffix), MB (with m or M suffix), and GB"
           " (with g or G suffix)\n"
           "-t (key:value ...)  - add tuple(s) to manifest\n"
           "-e                  - create empty filesystem\n",
           p, p);
}

boolean parse_size(const char *str, long long *size)
{
    char *endptr;
    long long img_size = strtoll(str, &endptr, 0);
    if (img_size <= 0)
        return false;
    switch (*endptr) {
    case 'k':
    case 'K':
        img_size *= KB;
        break;
    case 'm':
    case 'M':
        img_size *= MB;
        break;
    case 'g':
    case 'G':
        img_size *= GB;
        break;
    case '\0':
        break;
    default:
        return false;
    }
    *size = img_size;
    return true;
}

vector cmdline_tuples;

closure_func_basic(parse_finish, void, cmdline_tuple_finish,
                   void *v)
{
    if (!is_tuple(v)) {
        msg_err("cmdline value is not a tuple: %v", v);
        exit(EXIT_FAILURE);
    }
    vector_push(cmdline_tuples, v);
}

closure_func_basic(parse_error, void, cmdline_tuple_err,
                   string s)
{
    msg_err("cmdline tuple parse error: %b", s);
    exit(EXIT_FAILURE);
}


closure_func_basic(binding_handler, boolean, cmdline_tuple_each,
                   void *k, void *v)
{
    set(root, k, v);
    return true;
}

int main(int argc, char **argv)
{
    int c;
    const char *bootimg_path = NULL;
    const char *kernelimg_path = NULL;
    sstring label = sstring_empty();
    const char *target_root = NULL;
    long long img_size = 0;
    long long coredumplimit = 0;
    boolean empty_fs = false;
    const char *uefi_loader = NULL;
    heap h = init_process_runtime();
    cmdline_tuples = allocate_vector(h, 4);
    assert(cmdline_tuples != INVALID_ADDRESS);

    while ((c = getopt(argc, argv, "eb:k:l:r:s:u:t:")) != EOF) {
        switch (c) {
        case 'e':
            empty_fs = true;
            break;
        case 'b':
            bootimg_path = optarg;
            break;
        case 'u':
            uefi_loader = optarg;
            break;
        case 'k':
            kernelimg_path = optarg;
            break;
        case 'l':
            if (strlen(optarg) >= VOLUME_LABEL_MAX_LEN) {
                printf("label '%s' too long\n", optarg);
                exit(EXIT_FAILURE);
            }
            label = isstring(optarg, strlen(optarg));
            break;
        case 'r':
            target_root = optarg;
            break;
        case 's': {
            if (!parse_size(optarg, &img_size)) {
                printf("invalid image file size %s\n", optarg);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 't': {
            buffer b = alloca_wrap_buffer(optarg, strlen(optarg));
            parser p = tuple_parser(h, stack_closure_func(parse_finish, cmdline_tuple_finish),
                                    stack_closure_func(parse_error, cmdline_tuple_err));
            parser_feed(p, b);
            break;
        }
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if (uefi_loader && !bootimg_path)
        halt("UEFI loader can only be supplied together with boot image\n");
    argc -= optind;

    if (argc == 0) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    argv += optind;
    const char *image_path = argv[0];

    descriptor out = open(image_path, O_CREAT|O_RDWR|O_TRUNC, 0644);
    if (out < 0) {
        halt("couldn't open output file %s: %s\n", image_path, errno_sstring());
    }

    // prepend boot image (if any)
    ssize_t offset = 0;
    if (bootimg_path != NULL) {
        descriptor in = open(bootimg_path, O_RDONLY);
        if (in < 0) {
            halt("couldn't open boot image file %s: %s\n", bootimg_path, errno_sstring());
        }

        char buf[PAGESIZE];
        ssize_t nr;
        while ((nr = read(in, buf, sizeof(buf))) > 0) {
            ssize_t nw;

            while (nr > 0) {
                nw = write(out, buf, nr);
                if (nw < 0) {
                    halt("couldn't write to output file %s: %s\n", image_path, errno_sstring());
                }
                offset += nw;
                nr -= nw;
            }
        }
        if (nr < 0) {
            halt("couldn't read from boot image file %s: %s\n", bootimg_path, errno_sstring());
        }

        /* The on-disk kernel log dump section is immediately before the first partition. */
        offset += KLOG_DUMP_SIZE;

        if (uefi_loader)
            offset = write_uefi_part(out, offset, uefi_loader);
    }

    if (empty_fs) {
        root = allocate_tuple();
        set(root, sym(children), allocate_tuple());
    } else {
        parser p = tuple_parser(h, stack_closure_func(parse_finish, finish),
                                stack_closure_func(parse_error, perr));
        parser_feed(p, read_stdin(h));
    }

    mkfs_write_status = closure_func(h, io_status_handler, mkfs_write_handler);

    if (root && !empty_fs) {
        /* apply commandline tuples to root */
        value v;
        vector_foreach(cmdline_tuples, v) {
            iterate(v, stack_closure_func(binding_handler, cmdline_tuple_each));
            deallocate_value(v);
        }
        deallocate_vector(cmdline_tuples);

        v = get(root, sym(imagesize));
        if (v) {
            set(root, sym(imagesize), 0); /* consume it, kernel doesn't need it */
            push_u8((buffer)v, 0);
            char *s = buffer_ref((buffer)v, 0);
            if (!parse_size(s, &img_size)) {
                printf("invalid imagesize string \"%s\"\n", s);
                exit(EXIT_FAILURE);
            }
            deallocate_buffer((buffer)v);
        }

        v = get(root, sym(coredumplimit));
        if (v) {
            char *cdl = buffer_to_cstring((buffer)v);
            if (!parse_size(cdl,  &coredumplimit)) {
                halt("invalid coredumplimit string \"%b\"\n", v);
            }
            if (coredumplimit > img_size)
                img_size = coredumplimit;
        }

        tuple boot = get_tuple(root, sym(boot));
        if (kernelimg_path != NULL) {
            if (!boot)
                boot = allocate_tuple();
            tuple children = find_or_allocate_tuple(boot, sym(children));
            tuple kernel = find_or_allocate_tuple(children, sym(kernel));
            tuple contents = find_or_allocate_tuple(kernel, sym(contents));
            buffer b = alloca_wrap_buffer(kernelimg_path, strlen(kernelimg_path));
            set(contents, sym(host), b);
            set(kernel, sym(contents), contents);
            set(children, sym(kernel), kernel);
            set(boot, sym(children), children);
        } else if (!boot) {
            /* Look for kernel file in root filesystem, for backward
             * compatibility. */
            tuple c = children(root);
            assert(c);
            tuple kernel = get_tuple(c, sym(kernel));
            if (kernel) {
                boot = allocate_tuple();
                c = allocate_tuple();
                set(boot, sym(children), c);
                set(c, sym(kernel), kernel);
            }
        }
        if (boot) {
            create_filesystem(h, SECTOR_SIZE, BOOTFS_SIZE, closure(h, bwrite, out, offset), false,
                              sstring_empty(), closure(h, fsc, h, out, boot, target_root));
            offset += BOOTFS_SIZE;

            /* Remove tuple from root, so it doesn't end up in the root FS. */
            set(root, sym(boot), 0);
        } else if (bootimg_path) {
            halt("kernel or boot FS not specified\n");
        }
    }

    create_filesystem(h,
                      SECTOR_SIZE,
                      infinity,
                      closure(h, bwrite, out, offset),
                      false,
                      label,
                      closure(h, fsc, h, out, root, target_root));

    off_t current_size = lseek(out, 0, SEEK_END);
    if (current_size < 0) {
        halt("could not get image size: %s\n", errno_sstring());
    }
    if (!img_size)
        img_size = current_size;
    img_size = pad(img_size - offset + TFS_LOG_DEFAULT_EXTENSION_SIZE,
                   TFS_LOG_DEFAULT_EXTENSION_SIZE) + offset;
    if (current_size < img_size) {
        if (ftruncate(out, img_size)) {
            halt("could not set image size: %s\n", errno_sstring());
        }
    }
    if (bootimg_path != NULL)
        write_mbr(out, uefi_loader != NULL);

    close(out);
    exit(0);
}
