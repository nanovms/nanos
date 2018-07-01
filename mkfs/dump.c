#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

typedef int descriptor;

static CLOSURE_1_3(bwrite, void, buffer, buffer, u64, status_handler);
static void bwrite(buffer d, buffer s, u64 offset, status_handler c)
{

}

static CLOSURE_1_4(bread, void, descriptor d, void *, u64, u64, status_handler);
static void bread(buffer b, void *dest, u64 offset, u64 length, status_handler c)
{
    rprintf("read! %p\n", offset);
    pread(d, dest, offset, length);
    apply(c, STATUS_OK);
}

static buffer files, contents;

static buffer read_stdin(heap h)
{
    buffer in = allocate_buffer(h, 1024);
    int r, k;
    while ((r = in->length - in->end) &&
           ((k = read(0, in->contents + in->end, r)), in->end += k, k == r)) 
        buffer_extend(in, 1024);
    return in;
}

boolean compare_bytes(void *a, void *b, bytes len);

void readdir(buffer b, u64 where);

// closures
void each(void *k, buffer b, u64 klen, void *k, u64 vlen, u64 voffset)
{
    char files = "files";
    char contents = "contents";
    char zed[32];
    memcpy(zed, k, klen);

    rprintf("%S key %s", *(unsigned int *)zed);
    if ((klen == sizeof(files)) && compare_bytes(files, k, klen)) {
        readdir(b, voffset);
    }
}

void readdir(void *k buffer b, u64 where)
{
    iterate(b, where, each, k); 
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    tuple root = allocate_tuple();
    filesystem fs = create_filesystem(h,
                                      SECTOR_SIZE,
                                      10ull * 1024 * 1024 * 1024,
                                      closure(h, bread, out),
                                      closure(h, bwrite, out),
                                      root));
}
