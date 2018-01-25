#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

static void *malloc_allocator(heap h, bytes s)
{
    return malloc(s);
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
    buffer b = read_stdin();
    unsigned int sp = 0;
    readdir(&sp, b, 0);
}
