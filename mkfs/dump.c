#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <tfs.h>
#include <errno.h>
#include <string.h>

static CLOSURE_1_3(bwrite, void, descriptor, void *, range, status_handler);
static void bwrite(descriptor d, void * s, range blocks, status_handler c)
{

}

static CLOSURE_1_3(bread, void, descriptor, void *, range, status_handler);
static void bread(descriptor d, void *dest, range blocks, status_handler c)
{
    ssize_t xfer, total = 0;
    u64 offset = blocks.start << SECTOR_OFFSET;
    u64 length = range_span(blocks) << SECTOR_OFFSET;
    while (total < length) {
        xfer = pread(d, dest + total, length - total, offset + total);
        if (xfer < 0 && errno != EINTR) {
            apply(c, timm("read-error", "%s", strerror(errno)));
            return;
        }
        total += xfer;
    }
    apply(c, STATUS_OK);
}


boolean compare_bytes(void *a, void *b, bytes len);

CLOSURE_1_1(write_file, void, buffer, buffer);
void write_file(buffer path, buffer b)
{
    // openat would be nicer really
    char *z = cstring(path);
    int fd = open(z, O_CREAT|O_WRONLY, 0644);
    size_t xfer, len = buffer_length(b);
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
}

// h just for extending path
// isn't there an internal readdir?
void readdir(filesystem fs, heap h, tuple w, buffer path)
{
    table_foreach(w, k, v) {
        if (k == sym(children)) {
            mkdir(cstring(path), 0777);
            table_foreach((tuple)v, k, vc) {
                readdir(fs, h, (tuple)vc, aprintf(h, "%b/%b", path, symbol_string((symbol)k)));
            }
        }
        if (k == sym(extents))
            filesystem_read_entire(fs, w, h, closure(h, write_file, path), (void *)ignore);
    }
}

static CLOSURE_3_2(fsc, void, heap, buffer, tuple, filesystem, status);
static void fsc(heap h, buffer b, tuple root, filesystem fs, status s)
{
    rprintf ("meta: %v\n", root);
    readdir(fs, h, root, b);
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    tuple root = allocate_tuple();

    if (argc < 3) {
        rprintf("usage: %s <fs image> <target dir>\n");
        exit(EXIT_FAILURE);
    }

    int fd = open(argv[1], O_RDONLY);

    if (fd < 0) {
        rprintf("couldn't open file %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    create_filesystem(h,
                      SECTOR_SIZE,
                      10ull * 1024 * 1024 * 1024,
                      h,
                      closure(h, bread, fd),
                      closure(h, bwrite, fd),
                      root,
                      closure(h, fsc, h, alloca_wrap_buffer(argv[2], runtime_strlen(argv[2])), root));
    return EXIT_SUCCESS;
}
