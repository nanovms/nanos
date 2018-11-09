#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <tfs.h>
#include <errno.h>

static CLOSURE_1_3(bwrite, void, descriptor, buffer, u64, status_handler);
static void bwrite(descriptor d, buffer s, u64 offset, status_handler c)
{

}

static CLOSURE_1_4(bread, void, descriptor, void *, u64, u64, status_handler);
static void bread(descriptor d, void *dest, u64 length, u64 offset, status_handler c)
{
    int xfer, total = 0;
    while (total < length) {
        xfer = pread(d, dest + total , length - total, offset + total);
        if (xfer == 0) apply(c, 0);
        if (xfer == -1) apply(c, timm("read-error", "%E", errno));
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
    write(fd, buffer_ref(b, 0), buffer_length(b));
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
    int fd = open(argv[1], O_RDONLY);

    if (fd < 0) {
        rprintf("couldn't open file %s\n", argv[1]);
        exit(-1);
    }
    create_filesystem(h,
                      SECTOR_SIZE,
                      10ull * 1024 * 1024 * 1024,
                      closure(h, bread, fd),
                      closure(h, bwrite, fd),
                      root,
                      closure(h, fsc, h, alloca_wrap_buffer(argv[2], runtime_strlen(argv[2])), root));
}
