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
           ((k = read(0, in->contents + in->end, r)), in->end += k, k > 0))
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
void read_file(heap h, const char *target_root, buffer dest, buffer name)
{
    buffer name_b = NULL;

    // mode bit metadata
    struct stat st;
    if (stat(cstring(name), &st) < 0) {
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
    u64 total = 0;
    while (total < size) {
        int rv = read(fd, buffer_ref(dest, total), size - total);
        if (rv < 0 && errno != EINTR) {
            close(fd);
            halt("file read error: %s\n", strerror(errno));
        }
        total += rv;
    }
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

static CLOSURE_1_3(bwrite, void, descriptor, void *, range, status_handler);
static void bwrite(descriptor d, void * s, range blocks, status_handler c)
{
    ssize_t start = blocks.start << SECTOR_OFFSET;
    ssize_t size = range_span(blocks) << SECTOR_OFFSET;
    ssize_t total = 0;
    while (total < size) {
        ssize_t rv = pwrite(d, s + total, size - total, start + total);
        if (rv < 0 && errno != EINTR) {
            apply(c, timm("error", "pwrite error: %s", strerror(errno)));
            return;
        }
        total += rv;
    }
    apply(c, STATUS_OK);
}

static CLOSURE_1_3(bread, void, descriptor, void *, range, status_handler);
static void bread(descriptor d, void *source, range blocks, status_handler completion)
{
    apply(completion, timm("error", "empty file"));
}

static CLOSURE_0_1(err, void, status);
static void err(status s)
{
    rprintf("reported error\n");
}

static buffer translate_contents(heap h, const char *target_root, value v)
{
    if (tagof(v) == tag_tuple) {
        value path = table_find((table)v, sym(host));
        if (path) {
            // seems like it wouldn't be to hard to arrange
            // for this to avoid the staging copy
            buffer dest = allocate_buffer(h, 1024);
            read_file(h, target_root, dest, path);
            return dest;
        }
    }
    return v;
}

// dont really like the file/tuple duality, but we need to get something running today,
// so push all the bodies onto a worklist
static value translate(heap h, vector worklist,
		       const char *target_root, filesystem fs, value v, status_handler sh)
{
    switch(tagof(v)) {
    case tag_tuple:
        {
            tuple out = allocate_tuple();
            table_foreach((table)v, k, child) {
                if (k == sym(contents)) {
                    vector_push(worklist, build_vector(h, out, translate_contents(h, target_root, child)));
                } else {
                    table_set(out, k, translate(h, worklist, target_root, fs, child, sh));
                }
            }
            return out;
        }
    default:
        return v;
    }
}

extern heap init_process_runtime();

static CLOSURE_3_2(fsc, void, heap, descriptor, const char *, filesystem, status);
static void fsc(heap h, descriptor out, const char *target_root, filesystem fs, status s)
{
    if (!root)
        exit(1);

    vector worklist = allocate_vector(h, 10);
    tuple md = translate(h, worklist, target_root, fs, root, closure(h, err));

    rprintf("metadata ");
    buffer b = allocate_buffer(transient, 64);
    print_tuple(b, md);
    debug(b);
    deallocate_buffer(b);
    rprintf("\n");

    filesystem_write_tuple(fs, md, ignore_status);
    vector i;
    vector_foreach(worklist, i) {
        tuple f = vector_get(i, 0);        
        buffer c = vector_get(i, 1);
        allocate_fsfile(fs, f);
        filesystem_write(fs, f, c, 0, ignore_io_status);
    }
    close(out);
}

static void usage(const char *program_name)
{
    const char *p = strrchr(program_name, '/');
    if (p != NULL)
        p++;
    else
        p = program_name;
    printf("Usage: %s [-r target-root] image-file < manifest-file\n"
           "\n"
	   "-r	- specify target root\n",
           p);
}

int main(int argc, char **argv)
{
    int c;
    const char *target_root = NULL;

    while ((c = getopt(argc, argv, "hr:")) != EOF) {
        switch (c) {
        case 'r':
            target_root = optarg;
	    break;
        default:
            usage(argv[0]);
	    exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    const char *image_path = argv[0];

    heap h = init_process_runtime();
    descriptor out = open(image_path, O_CREAT|O_WRONLY, 0644);
    u64 fs_size = 100ull * MB;  /* XXX temp, change to infinity after rtrie/bitmap fix */
    if (out < 0) {
        halt("couldn't open output file %s\n", image_path);
    }

    parser p = tuple_parser(h, closure(h, finish, h), closure(h, perr));
    // this can be streaming
    parser_feed (p, read_stdin(h));
    // fixing the size doesn't make sense in this context?
    create_filesystem(h,
                      SECTOR_SIZE,
                      fs_size,
                      h,
                      closure(h, bread, out),
                      closure(h, bwrite, out),
                      allocate_tuple(),
                      closure(h, fsc, h, out, target_root));
    exit(0);
}
