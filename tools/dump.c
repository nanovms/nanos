#include <runtime.h>

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdio.h>
#include <storage.h>
#include <tfs.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <log.h>

#define DUMP_OPT_TREE  (1U << 0)

#define TERM_COLOR_BLUE     94
#define TERM_COLOR_CYAN     96
#define TERM_COLOR_WHITE    97
#define TERM_COLOR_DEFAULT  0

closure_function(2, 1, void, bread,
                 descriptor, d, u64, fs_offset,
                 storage_req req)
{
    if (req->op != STORAGE_OP_READSG)
        halt("%s: invalid storage op %d\n", func_ss, req->op);
    sg_list sg = req->data;
    u64 offset = bound(fs_offset) + (req->blocks.start << SECTOR_OFFSET);
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
        xfer = readv(bound(d), iov, iov_count);
        if (xfer < 0 && errno != EINTR) {
            apply(req->completion, timm("result", "read error %s", errno_sstring()));
            return;
        }
        if (xfer == 0) {
            apply(req->completion, timm("result", "end of file"));
            return;
        }
        sg_consume(sg, xfer);
        total -= xfer;
    }
    apply(req->completion, STATUS_OK);
}

closure_function(1, 1, status, write_file,
                 buffer, path,
                 buffer b)
{
    // openat would be nicer really
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    char *z = cstring(bound(path), tmpbuf);
    int fd = open(z, O_CREAT|O_WRONLY, 0644);
    ssize_t xfer, len = buffer_length(b);
    while (len > 0) {
        xfer = write(fd, buffer_ref(b, 0), len);
        if (xfer < 0 && errno != EINTR) {
            perror("file write");
            close(fd);
            exit(EXIT_FAILURE);
        }
        len -= xfer;
        buffer_consume(b, xfer);
    }
    close(fd);
    return STATUS_OK;
}

void readdir(filesystem fs, heap h, tuple w, buffer path);

closure_function(3, 2, boolean, readdir_each_child,
                 filesystem, fs, heap, h, buffer, path,
                 value k, value v)
{
    assert(is_symbol(k));
    if (k == sym_this(".") || k == sym_this(".."))
        return true;
    assert(is_tuple(v));
    readdir(bound(fs), bound(h), (tuple)v, aprintf(bound(h), "%b/%b", bound(path), symbol_string(k)));
    return true;
}

// h just for extending path
// isn't there an internal readdir?
void readdir(filesystem fs, heap h, tuple w, buffer path)
{
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    tuple t = get_tuple(w, sym(children));
    if (t) {
        mkdir(cstring(path, tmpbuf), 0777);
        iterate(t, stack_closure(readdir_each_child, fs, h, path));
    } else {
        t = get_tuple(w, sym(extents));
        if (t)
            filesystem_read_entire(fs, w, h, closure(h, write_file, path), (void *)ignore);
    }
}

static void print_colored(int indent, int color, symbol s, boolean newline)
{
    while (indent--)
        console("|   ");
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    printf("\e[%dm%s\e[%dm%s", color, cstring(symbol_string(s), tmpbuf),
           TERM_COLOR_DEFAULT, newline ? "\n" : "");
}

static void dump_fsentry(int indent, symbol name, tuple t);

closure_function(1, 2, boolean, dump_fsentry_each,
                 int, indent,
                 value k, value vc)
{
    assert(is_symbol(k));
    if (k == sym_this(".") || k == sym_this(".."))
        return true;
    assert(is_tuple(vc));
    dump_fsentry(bound(indent) + 1, k, (tuple)vc);
    return true;
}

static void dump_fsentry(int indent, symbol name, tuple t)
{
    tuple c;
    buffer target_buf;
    if ((c = children(t))) {
        print_colored(indent, TERM_COLOR_BLUE, name, true);
        iterate(c, stack_closure(dump_fsentry_each, indent));
    } else if ((target_buf = get(t, sym(linktarget)))) {
        buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
        print_colored(indent, TERM_COLOR_CYAN, name, false);
        printf(" -> %s\n", cstring(target_buf, tmpbuf));
    } else
        print_colored(indent, TERM_COLOR_WHITE, name, true);
}

closure_function(3, 2, void, fsc,
                 heap, h, buffer, b, unsigned int, options,
                 filesystem fs, status s)
{
    heap h = bound(h);

    if (!is_ok(s)) {
        rprintf("failed to initialize filesystem: %v\n", s);
        exit(EXIT_FAILURE);
    }

    unsigned int options = bound(options);
    u8 uuid[UUID_LEN];
    filesystem_get_uuid(fs, uuid);
    tuple root = filesystem_getroot(fs);
    buffer rb = allocate_buffer(h, PAGESIZE);
    bprintf(rb, "Label: %s\n", filesystem_get_label(fs));
    bprintf(rb, "UUID: ");
    print_uuid(rb, uuid);
    if (!(options & DUMP_OPT_TREE)) {
        bprintf(rb, "\nmetadata\n");
        print_value(rb, root, timm("indent", "0"));
    }
    buffer_print(rb);
    rprintf("\n");
    deallocate_buffer(rb);

    buffer b = bound(b);
    if (b)
        readdir(fs, h, root, b);

    if (options & DUMP_OPT_TREE)
        dump_fsentry(0, sym_this("/"), root);

    closure_finish();
}

static u64 get_fs_offset(descriptor fd, int part, boolean by_index)
{
    char buf[512];

    ssize_t nr = read(fd, buf, sizeof(buf));
    if (nr < 0 || nr < sizeof(buf)) {
        perror("read");
	exit(EXIT_FAILURE);
    }

    struct partition_entry *rootfs_part =
            (by_index ? partition_at(buf, part) : partition_get(buf, part));

    if (!rootfs_part || rootfs_part->lba_start == 0 ||
            rootfs_part->nsectors == 0) {
        // probably raw filesystem
        return 0;
    }

    u64 fs_offset = rootfs_part->lba_start * SECTOR_SIZE;
    printf("detected filesystem at 0x%llx\n", fs_offset);
    return fs_offset;
}

static void dump_klog(int fd)
{
    u64 i, off;

    off = get_fs_offset(fd, 0, true);
    if (off == 0) {
        fprintf(stderr, "no boot filesystem found\n");
        exit(EXIT_FAILURE);
    }
    /* The klog ends at the start of the first partition, but has a configurable size,
     * so work backwards from the end to find the start magic
     */
    for (i = off - SECTOR_SIZE; i > 0; i -= SECTOR_SIZE) {
        u8 hdr[16];
        if (pread(fd, hdr, sizeof(hdr), i) != sizeof(hdr)) {
            fprintf(stderr, "error reading offset %llu\n", i);
            exit(EXIT_FAILURE);
        }
        if (memcmp(hdr, "KLOG", 4) == 0)
            break;
    }
    if (i <= 0) {
        fprintf(stderr, "no crash log found on image\n");
        exit(EXIT_SUCCESS);
    }
    int klog_size = off - i;
    printf("klog offset: 0x%llx\nklog size: %d bytes\n", i, klog_size);
    u8 *buf = malloc(klog_size);
    if (pread(fd, buf, klog_size, i) != klog_size) {
        fprintf(stderr, "error reading klog\n");
        exit(EXIT_FAILURE);
    }
    klog_dump klog = (klog_dump)buf;
    printf("boot id: %llx\nexit code: %d\n\n", klog->boot_id, klog->exit_code);
    printf("%.*s\n", klog_size - 16, klog->msgs);
    exit(EXIT_SUCCESS);
}

static void usage(const char *prog)
{
    const char *p = strrchr(prog, '/');
    p = p != NULL ? p + 1 : prog;
    fprintf(stderr, "Usage: %s [OPTION]... <fs image>\n", p);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d <target dir>\tCopy filesystem contents from "
            "<fs image> into <target dir>\n");
    fprintf(stderr, "  -t\t\t\tDisplay filesystem from <fs image> as a tree\n");
    fprintf(stderr, "  -l\t\t\tDisplay contents of crash log\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    buffer target_dir = NULL;
    int c;
    unsigned int options = 0;
    boolean print_klog = false;

    while ((c = getopt(argc, argv, "d:tl")) != EOF) {
        switch (c) {
        case 'd':
            target_dir = alloca_wrap_buffer(optarg, strlen(optarg));
            break;
        case 't':
            options |= DUMP_OPT_TREE;
            break;
        case 'l':
            print_klog = true;
            break;
        default:
            usage(argv[0]);
        }
    }
    if (optind == argc)
        usage(argv[0]);

    int fd = open(argv[optind], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "couldn't open file %s: %s\n", argv[optind],
            strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (print_klog)
        dump_klog(fd);

    heap h = init_process_runtime();
    create_filesystem(h,
                      SECTOR_SIZE,
                      infinity,
                      closure(h, bread, fd, get_fs_offset(fd, PARTITION_ROOTFS, false)),
                      true, sstring_null(), /* read only, no label */
                      closure(h, fsc, h, target_dir, options));
    return EXIT_SUCCESS;
}
