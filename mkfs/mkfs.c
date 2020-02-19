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

#include <region.h>

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
            buffer_write(target_name, target_root, strlen(target_root));
            if (n[0] != '/')
                buffer_write_byte(target_name, '/');
            buffer_write(target_name, n, len);

            if (lstat(cstring(target_name, tmpbuf), st) < 0) {
                if (errno != ENOENT)
                    halt("couldn't stat file %b: %s\n", target_name, strerror(errno));

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
                halt("couldn't readlink file %b: %s\n", name, strerror(errno));
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
        halt("couldn't stat file %b: %s\n", name, strerror(errno));
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
    if (fd < 0) halt("couldn't open file %b: %s\n", name, strerror(errno));
    u64 size = st.st_size;
    buffer_extend(dest, pad(st.st_size, SECTOR_SIZE));
    u64 total = 0;
    while (total < size) {
        int rv = read(fd, buffer_ref(dest, total), size - total);
        if (rv < 0 && errno != EINTR) {
            close(fd);
            halt("read: %b: %s\n", name, strerror(errno));
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
closure_function(1, 1, void, finish,
                 heap, h,
                 void *, v)
{
    root = v;
}

closure_function(0, 1, void, perr,
                 string, s)
{
    rprintf("parse error %b\n", s);
}

closure_function(2, 3, void, bwrite,
                 descriptor, d, ssize_t, offset,
                 void *, s, range, blocks, status_handler, c)
{
    ssize_t start = blocks.start << SECTOR_OFFSET;
    ssize_t size = range_span(blocks) << SECTOR_OFFSET;
    ssize_t total = 0;
    while (total < size) {
        ssize_t rv = pwrite(bound(d), s + total, size - total, bound(offset) + start + total);
        if (rv < 0 && errno != EINTR) {
            apply(c, timm("error", "pwrite error: %s", strerror(errno)));
            return;
        }
        total += rv;
    }
    apply(c, STATUS_OK);
}

closure_function(0, 1, void, err,
                 status, s)
{
    rprintf("reported error\n");
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
                    vector_push(worklist, build_vector(h, out, child));
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

closure_function(3, 2, void, fsc,
                 heap, h, descriptor, out, const char *, target_root,
                 filesystem, fs, status, s)
{
    if (!root)
        exit(1);

    heap h = bound(h);
    vector worklist = allocate_vector(h, 10);
    tuple md = translate(h, worklist, bound(target_root), fs, root, closure(h, err));

    rprintf("metadata ");
    buffer b = allocate_buffer(transient, 64);
    print_tuple(b, md);
    buffer_print(b);
    deallocate_buffer(b);
    rprintf("\n");

    filesystem_write_tuple(fs, md, ignore_status);
    vector i;
    vector_foreach(worklist, i) {
        tuple f = vector_get(i, 0);        
        buffer contents = get_file_contents(h, bound(target_root), vector_get(i, 1));
        if (contents) {
            allocate_fsfile(fs, f);
            filesystem_write(fs, f, contents, 0, ignore_io_status);
            deallocate_buffer(contents);
        }
    }
}

struct partition_entry {
    u8 active;
    u8 chs_start[3];
    u8 type;
    u8 chs_end[3];
    u32 lba_start;
    u32 nsectors;
} __attribute__((packed));

#define SEC_PER_TRACK 63
#define HEADS 255
#define MAX_CYL 1023

static void mbr_chs(u8 *chs, u64 offset)
{
    u64 cyl = ((offset / SECTOR_SIZE) / SEC_PER_TRACK) / HEADS;
    u64 head = ((offset / SECTOR_SIZE) / SEC_PER_TRACK) % HEADS;
    u64 sec = ((offset / SECTOR_SIZE) % SEC_PER_TRACK) + 1;
    if (cyl > MAX_CYL) {
        cyl = MAX_CYL;
	head = 254;
	sec = 63;
    }

    chs[0] = head;
    chs[1] = (cyl >> 8) | sec;
    chs[2] = cyl & 0xff;
}

static void write_mbr(descriptor f)
{
    // get resulting size
    off_t total_size = lseek(f, 0, SEEK_END);
    if (total_size < 0)
        halt("could not get image size: %s\n", strerror(errno));
    assert(total_size % SECTOR_SIZE == 0);

    // read MBR
    char buf[SECTOR_SIZE];
    int res = pread(f, buf, sizeof(buf), 0);
    if (res < 0)
        halt("could not read MBR: %s\n", strerror(errno));
    else if (res != sizeof(buf))
        halt("could not read MBR (short read)\n");

    // MBR signature
    u16 *mbr_sig = (u16 *) (buf + sizeof(buf) - sizeof(*mbr_sig));
    if (*mbr_sig != 0xaa55)
        halt("invalid MBR signature\n");

    // first MBR partition entry
    struct partition_entry *e = (struct partition_entry *) ((char *) mbr_sig - 4 * sizeof(*e));

    // FS region comes right before MBR partitions (see boot/stage1.s)
    region r = (region) ((char *) e - sizeof(*r));
    if (r->type != REGION_FILESYSTEM)
        halt("invalid boot record (missing filesystem region) \n");
    u64 fs_offset = SECTOR_SIZE + r->length;
    assert(fs_offset % SECTOR_SIZE == 0);
    assert(total_size > fs_offset);

    // create partition entry
    e->active = 0x80;      // active, bootable
    e->type = 0x83;        // any Linux filesystem
    mbr_chs(e->chs_start, fs_offset);
    mbr_chs(e->chs_end, total_size - SECTOR_SIZE);
    e->lba_start = fs_offset / SECTOR_SIZE;
    e->nsectors = (total_size - fs_offset) / SECTOR_SIZE;

    // write MBR
    res = pwrite(f, buf, sizeof(buf), 0);
    if (res < 0)
        halt("could not write MBR: %s\n", strerror(errno));
    else if (res != sizeof(buf))
        halt("could not write MBR (short write)\n");
}

static void usage(const char *program_name)
{
    const char *p = strrchr(program_name, '/');
    p = p != NULL ? p + 1 : program_name;
    printf("Usage: %s [-b boot-image] [-r target-root] image-file < manifest-file\n"
           "\n"
           "-b	- specify boot image to prepend\n"
           "-r	- specify target root\n",
           p);
}

int main(int argc, char **argv)
{
    int c;
    const char *bootimg_path = NULL;
    const char *target_root = NULL;

    while ((c = getopt(argc, argv, "hb:r:")) != EOF) {
        switch (c) {
        case 'b':
            bootimg_path = optarg;
            break;
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
    descriptor out = open(image_path, O_CREAT|O_RDWR, 0644);
    if (out < 0) {
        halt("couldn't open output file %s: %s\n", image_path, strerror(errno));
    }

    // prepend boot image (if any)
    ssize_t offset = 0;
    if (bootimg_path != NULL) {
        descriptor in = open(bootimg_path, O_RDONLY);
        if (in < 0) {
            halt("couldn't open boot image file %s: %s\n", bootimg_path, strerror(errno));
        }

        char buf[PAGESIZE];
        ssize_t nr;
        while ((nr = read(in, buf, sizeof(buf))) > 0) {
            ssize_t nw;

            while (nr > 0) {
                nw = write(out, buf, nr);
                if (nw < 0) {
                    halt("couldn't write to output file %s: %s\n", image_path, strerror(errno));
                }
                offset += nw;
                nr -= nw;
            }
        }
        if (nr < 0) {
            halt("couldn't read from boot image file %s: %s\n", bootimg_path, strerror(errno));
        }
    }

    parser p = tuple_parser(h, closure(h, finish, h), closure(h, perr));
    // this can be streaming
    parser_feed (p, read_stdin(h));
    // fixing the size doesn't make sense in this context?
    create_filesystem(h,
                      SECTOR_SIZE,
                      SECTOR_SIZE,
                      infinity,
                      h,
                      0, /* no read -> new fs */
                      closure(h, bwrite, out, offset),
                      allocate_tuple(),
                      true,
                      closure(h, fsc, h, out, target_root));

    if (bootimg_path != NULL)
        write_mbr(out);

    close(out);
    exit(0);
}
