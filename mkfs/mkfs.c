#include <runtime.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <tfs.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>

static buffer read_stdin(heap h)
{
    buffer in = allocate_buffer(h, 1024);
    int r, k;
    while ((r = in->length - in->end) &&
           ((k = read(0, in->contents + in->end, r)), in->end += k, k == r)) 
        buffer_extend(in, 1024);
    return in;
}

buffer lookup_file(heap h, const char *target_root, buffer name, struct stat *st)
{
    char path_buf[PATH_MAX];
    const char *n = buffer_ref(name, 0);
    int len = buffer_length(name);

    name = allocate_buffer(h, PATH_MAX); // new buffer

    while (1) {
        buffer_clear(name);
        buffer_write(name, target_root, strlen(target_root));
        if (n[0] != '/')
            buffer_write_byte(name, '/');
        buffer_write(name, n, len);

        if (lstat(cstring(name), st) < 0)
           halt("couldn't stat file %b: %s\n", name, strerror(errno));
        if (!S_ISLNK(st->st_mode))
           break;

        if ((len = readlink(cstring(name), path_buf, sizeof(path_buf))) < 0)
           halt("couldn't readlink file %b: %s\n", name, strerror(errno));
        if (path_buf[0] == '/') {
            /* absolute links need to be resolved */
            n = path_buf;
            continue;
        }

        /* relative links are ok */
        if (stat(cstring(name), st) < 0)
            halt("couldn't stat file %b: %s\n", name, strerror(errno));
        break;
    }

    return name;
}

// its nice that we can append a file to any existing buffer, but harsh we have to grow the buffer
void read_file(heap h, buffer dest, buffer name)
{
    buffer name_b = NULL;

    // mode bit metadata
    struct stat st;
    if (stat(cstring(name), &st) < 0) {
#ifdef DEV
        const char *target_root = getenv("NANOS_TARGET_ROOT");
#else
        const char *target_root = NULL;
#endif
        if (target_root == NULL)
            halt("couldn't open file %b: %s\n", name, strerror(errno));

        name_b = lookup_file(h, target_root, name, &st);
        //printf("%s -> %s\n", cstring(name), cstring(name_b));
        name = name_b;
    }
    int fd = open(cstring(name), O_RDONLY);
    if (fd < 0) halt("couldn't open file %b: %s\n", name, strerror(errno));
    u64 size = st.st_size;
    buffer_extend(dest, pad(st.st_size, SECTOR_SIZE));
    read(fd, buffer_ref(dest, 0), size);
    dest->end += size;
    close(fd);

    if (name_b != NULL)
        deallocate_buffer(name_b);
}

heap malloc_allocator();

tuple root;
CLOSURE_1_1(finish, void, heap, void*);
void finish(heap h, void *v)
{
    root = v;
}

CLOSURE_0_1(perr, void, string);
void perr(string s)
{
    rprintf("parse error %b\n", s);
}

// status
void includedir(tuple dest, buffer path)
{
    DIR *d = opendir(cstring(path));
    while (readdir(d)) {
    }
    closedir(d);
}


static CLOSURE_1_3(bwrite, void, descriptor, buffer, u64, status_handler);
static void bwrite(descriptor d, buffer s, u64 offset, status_handler c)
{
    pwrite(d, buffer_ref(s, 0), buffer_length(s),  offset);
    apply(c, STATUS_OK);
}

static CLOSURE_1_4(bread, void, descriptor, void *, u64, u64, status_handler);
static void bread(descriptor d, void *source, u64 length, u64 offset, status_handler completion)
{
    apply(completion, timm("error", "empty file"));
}

static CLOSURE_0_1(err, void, status);
static void err(status s)
{
    rprintf("reported error\n");
}

static buffer translate_contents(heap h, value v)
{
    if (tagof(v) == tag_tuple) {
        value path = table_find((table)v, sym(host));
        if (path) {
            // seems like it wouldn't be to hard to arrange
            // for this to avoid the staging copy
            buffer dest = allocate_buffer(h, 1024);
            read_file(h, dest, path);
            return dest;
        }
    }
    return v;
}

// dont really like the file/tuple duality, but we need to get something running today,
// so push all the bodies onto a worklist
static value translate(heap h, vector worklist, filesystem fs, value v, status_handler sh)
{
    switch(tagof(v)) {
    case tag_tuple:
        {
            tuple out = allocate_tuple();
            table_foreach((table)v, k, child) {
                if (k == sym(contents)) {
                    vector_push(worklist, build_vector(h, out, translate_contents(h, child)));
                } else {
                    table_set(out, k, translate(h, worklist, fs, child, sh));
                }
            }
            return out;
        }
    default:
        return v;
    }
}

extern heap init_process_runtime();
#include <stdio.h>

static CLOSURE_2_2(fsc, void, heap, descriptor, filesystem, status);
static void fsc(heap h, descriptor out, filesystem fs, status s)
{
    if (!root)
        exit(1);

    vector worklist = allocate_vector(h, 10);
    tuple md = translate(h, worklist, fs, root, closure(h, err));
    rprintf ("metadata %v\n", md);
    filesystem_write_tuple(fs, md);
    vector i;
    vector_foreach(worklist, i) {
        tuple f = vector_get(i, 0);        
        buffer c = vector_get(i, 1);
        allocate_fsfile(fs, f);
        filesystem_write(fs, f, c, 0, ignore_io_status);
    }
    flush(fs, ignore_status);
    close(out);
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    descriptor out = open(argv[1], O_CREAT|O_WRONLY, 0644);
    u64 fs_size = 100ull * MB;  /* XXX temp, change to infinity after rtrie/bitmap fix */
    if (out < 0) {
        halt("couldn't open output file %s\n", argv[1]);
    }

    parser p = tuple_parser(h, closure(h, finish, h), closure(h, perr));
    // this can be streaming
    parser_feed (p, read_stdin(h));
    // fixing the size doesn't make sense in this context?
    create_filesystem(h,
                      SECTOR_SIZE,
                      fs_size,
                      closure(h, bread, out),
                      closure(h, bwrite, out),
                      allocate_tuple(),
                      closure(h, fsc, h, out));
}
