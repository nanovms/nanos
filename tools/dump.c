#include <runtime.h>
#include <region.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <pagecache.h>
#include <tfs.h>
#include <storage.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#define DUMP_OPT_TREE  (1U << 0)

#define TERM_COLOR_BLUE     94
#define TERM_COLOR_CYAN     96
#define TERM_COLOR_WHITE    97

closure_function(2, 3, void, bread,
                 descriptor, d, u64, fs_offset,
                 void *, dest, range, blocks, status_handler, c)
{
    ssize_t xfer, total = 0;
    u64 offset = bound(fs_offset) + (blocks.start << SECTOR_OFFSET);
    u64 length = range_span(blocks) << SECTOR_OFFSET;
    while (total < length) {
        xfer = pread(bound(d), dest + total, length - total, offset + total);
        if (xfer < 0 && errno != EINTR) {
            apply(c, timm("read-error", "%s", strerror(errno)));
            return;
        }
        total += xfer;
    }
    apply(c, STATUS_OK);
}

closure_function(1, 1, status, write_file,
                 buffer, path,
                 buffer, b)
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

// h just for extending path
// isn't there an internal readdir?
void readdir(filesystem fs, heap h, tuple w, buffer path)
{
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    table_foreach(w, k, v) {
        if (k == sym(children)) {
            mkdir(cstring(path, tmpbuf), 0777);
            table_foreach((tuple)v, k, vc) {
                if (k == sym_this(".") || k == sym_this(".."))
                    continue;
                readdir(fs, h, (tuple)vc, aprintf(h, "%b/%b", path, symbol_string((symbol)k)));
            }
        }
        if (k == sym(extents))
            filesystem_read_entire(fs, w, h, closure(h, write_file, path), (void *)ignore);
    }
}

static void print_colored(int indent, int color, symbol s, boolean newline)
{
    while (indent--)
        console("|   ");
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    printf("\e[%dm%s\e[%dm%s", color, cstring(symbol_string(s), tmpbuf),
           TERM_COLOR_WHITE, newline ? "\n" : "");
}

static void dump_fsentry(int indent, symbol name, tuple t)
{
    table c;
    buffer target_buf;
    if ((c = children(t))) {
        print_colored(indent, TERM_COLOR_BLUE, name, true);
        table_foreach((tuple)c, k, vc) {
            if (k == sym_this(".") || k == sym_this(".."))
                continue;
            dump_fsentry(indent + 1, (symbol)k, (tuple)vc);
        }
    } else if ((target_buf = table_find(t, sym(linktarget)))) {
        buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
        print_colored(indent, TERM_COLOR_CYAN, name, false);
        printf(" -> %s\n", cstring(target_buf, tmpbuf));
    } else
        print_colored(indent, TERM_COLOR_WHITE, name, true);
}

closure_function(4, 2, void, fsc,
                 heap, h, buffer, b, tuple, root, unsigned int, options,
                 filesystem, fs, status, s)
{
    heap h = bound(h);

    if (!is_ok(s)) {
        rprintf("failed to initialize filesystem: %v\n", s);
        exit(EXIT_FAILURE);
    }

    tuple root = bound(root);
    buffer rb = allocate_buffer(h, PAGESIZE);
    print_root(rb, root);
    buffer_print(rb);
    rprintf("\n");
    deallocate_buffer(rb);

    buffer b = bound(b);
    if (b)
        readdir(fs, h, root, b);

    unsigned int options = bound(options);
    if (options & DUMP_OPT_TREE)
        dump_fsentry(0, sym_this("/"), root);

    closure_finish();
}

static u64 get_fs_offset(descriptor fd)
{
    char buf[512];

    ssize_t nr = read(fd, buf, sizeof(buf));
    if (nr < 0 || nr < sizeof(buf)) {
        perror("read");
	exit(EXIT_FAILURE);
    }

    struct partition_entry *rootfs_part = partition_get(buf, PARTITION_ROOTFS);

    if (rootfs_part->lba_start == 0 ||
            rootfs_part->nsectors == 0) {
        // probably raw filesystem
        return 0;
    }

    u64 fs_offset = rootfs_part->lba_start * SECTOR_SIZE;
    rprintf("detected filesystem at 0x%lx\n", fs_offset);
    return fs_offset;
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
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    buffer target_dir = NULL;
    int c;
    unsigned int options = 0;

    while ((c = getopt(argc, argv, "d:t")) != EOF) {
        switch (c) {
        case 'd':
            target_dir = alloca_wrap_buffer(optarg, runtime_strlen(optarg));
            break;
        case 't':
            options |= DUMP_OPT_TREE;
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

    heap h = init_process_runtime();
    tuple root = allocate_tuple();
    pagecache pc = allocate_pagecache(h, h, 0, PAGESIZE);
    assert(pc != INVALID_ADDRESS);
    create_filesystem(h,
                      SECTOR_SIZE,
                      infinity,
                      closure(h, bread, fd, get_fs_offset(fd)),
                      0, /* no write */
                      pc,
                      root,
                      false,
                      closure(h, fsc, h, target_dir, root, options));
    return EXIT_SUCCESS;
}
