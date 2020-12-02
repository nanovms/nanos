#include <runtime.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <pagecache.h>
#include <tfs.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>

#include <region.h>
#include <storage.h>

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

static io_status_handler mkfs_write_status;
closure_function(0, 2, void, mkfs_write_handler,
                 status, s, bytes, length)
{
    if (!is_ok(s)) {
        rprintf("write failed with %v\n", s);
        exit(1);
    }
}

closure_function(4, 2, void, fsc,
                 heap, h, descriptor, out, tuple, root, const char *, target_root,
                 filesystem, fs, status, s)
{
    tuple root = bound(root);
    if (!root)
        exit(1);

    heap h = bound(h);
    vector worklist = allocate_vector(h, 10);
    tuple md = translate(h, worklist, bound(target_root), fs, root, closure(h, err));

    buffer b = allocate_buffer(transient, 64);
    u8 uuid[UUID_LEN];
    filesystem_get_uuid(fs, uuid);
    bprintf(b, "UUID: ");
    print_uuid(b, uuid);
    bprintf(b, "\nmetadata ");
    print_tuple(b, md);
    buffer_print(b);
    deallocate_buffer(b);
    rprintf("\n");

    filesystem_write_tuple(fs, md);
    vector i;
    buffer off = 0;
    vector_foreach(worklist, i) {
        tuple f = vector_get(i, 0);
        buffer contents = get_file_contents(h, bound(target_root), vector_get(i, 1));
        if (contents) {
            if (buffer_length(contents) > 0) {
                fsfile fsf = allocate_fsfile(fs, f);
                filesystem_write_linear(fsf, buffer_ref(contents, 0), irangel(0, buffer_length(contents)),
                                        ignore_io_status);
                deallocate_buffer(contents);
            } else {
                if (!off)
                    off = wrap_buffer_cstring(h, "0");
                /* make an empty file */
                filesystem_write_eav(fs, f, sym(extents), allocate_tuple());
                filesystem_write_eav(fs, f, sym(filelength), off);
            }
        }
    }
    filesystem_flush(fs, ignore_status);
    closure_finish();
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

    // first MBR partition entry
    struct partition_entry *e = partition_get(buf, 0);
    if (!e)
        halt("invalid MBR signature\n");

    // FS region comes right before MBR partitions (see boot/stage1.s)
    region r = (region) ((char *) e - sizeof(*r));
    if (r->type != REGION_FILESYSTEM)
        halt("invalid boot record (missing filesystem region) \n");
    u64 fs_offset = SECTOR_SIZE + r->length;
    assert(fs_offset % SECTOR_SIZE == 0);
    u64 fs_size = BOOTFS_SIZE;
    partition_write(&e[PARTITION_BOOTFS], true, 0x83, fs_offset, fs_size);

    /* Root filesystem */
    fs_offset += fs_size;
    assert(total_size > fs_offset);
    partition_write(&e[PARTITION_ROOTFS], true, 0x83, fs_offset,
                    total_size - fs_offset);

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
    printf("Usage:\n%s [options] image-file < manifest-file\n"
           "%s [options] -e image-file\n"
           "Options:\n"
           "-b boot-image	- specify boot image to prepend\n"
           "-k kern-image	- specify kernel image\n"
           "-l label	- specify filesystem label\n"
           "-r target-root	- specify target root\n"
           "-s image-size	- specify minimum image file size; can be expressed"
           " in bytes, KB (with k or K suffix), MB (with m or M suffix), and GB"
           " (with g or G suffix)\n"
           "-e              - create empty filesystem\n",
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

int main(int argc, char **argv)
{
    int c;
    const char *bootimg_path = NULL;
    const char *kernelimg_path = NULL;
    const char *label = "";
    const char *target_root = NULL;
    long long img_size = 0;
    boolean empty_fs = false;

    while ((c = getopt(argc, argv, "eb:k:l:r:s:")) != EOF) {
        switch (c) {
        case 'e':
            empty_fs = true;
            break;
        case 'b':
            bootimg_path = optarg;
            break;
        case 'k':
            kernelimg_path = optarg;
            break;
        case 'l':
            if (strlen(optarg) >= VOLUME_LABEL_MAX_LEN) {
                printf("label '%s' too long\n", optarg);
                exit(1);
            }
            label = optarg;
            break;
        case 'r':
            target_root = optarg;
            break;
        case 's': {
            if (!parse_size(optarg, &img_size)) {
                printf("invalid image file size %s\n", optarg);
                usage(argv[0]);
                exit(1);
            }
            break;
        }
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    const char *image_path = argv[0];

    heap h = init_process_runtime();
    descriptor out = open(image_path, O_CREAT|O_RDWR|O_TRUNC, 0644);
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

    if (offset >= (1 << 16)) {
        halt("boot image size (%d) exceeds 64KB; either trim stage2 or "
             "update readsectors in stage1\n", offset);
    }

    if (empty_fs) {
        root = allocate_tuple();
        table_set(root, sym(children), allocate_tuple());
    } else {
        parser p = tuple_parser(h, closure(h, finish, h), closure(h, perr));
        // this can be streaming
        parser_feed (p, read_stdin(h));
    }

    init_pagecache(h, h, 0, PAGESIZE);
    mkfs_write_status = closure(h, mkfs_write_handler);

    if (root && !empty_fs) {
        value v = table_find(root, sym(imagesize));
        if (v && tagof(v) != tag_tuple) {
            table_set(root, sym(imagesize), 0); /* consume it, kernel doesn't need it */
            push_u8((buffer)v, 0);
            char *s = buffer_ref((buffer)v, 0);
            if (!parse_size(s, &img_size)) {
                halt("invalid imagesize string \"%s\"\n", s);
            }
            deallocate_buffer((buffer)v);
        }

        tuple boot = table_find(root, sym(boot));
        if (kernelimg_path != NULL) {
            if (!boot)
                boot = allocate_tuple();
            tuple children = find_or_allocate_tuple(boot, sym(children));
            tuple kernel = find_or_allocate_tuple(children, sym(kernel));
            tuple contents = find_or_allocate_tuple(kernel, sym(contents));
            buffer b = alloca_wrap_buffer(kernelimg_path, runtime_strlen(kernelimg_path));
            table_set(contents, sym(host), b);
            table_set(kernel, sym(contents), contents);
            table_set(children, sym(kernel), kernel);
            table_set(boot, sym(children), children);
        } else if (!boot) {
            /* Look for kernel file in root filesystem, for backward
             * compatibility. */
            tuple c = children(root);
            assert(c);
            tuple kernel = table_find(c, sym(kernel));
            if (kernel) {
                boot = allocate_tuple();
                c = allocate_tuple();
                table_set(boot, sym(children), c);
                table_set(c, sym(kernel), kernel);
            }
        }
        if (boot) {
            create_filesystem(h, SECTOR_SIZE, BOOTFS_SIZE, 0,
                              closure(h, bwrite, out, offset),
                              "", closure(h, fsc, h, out, boot, target_root));
            offset += BOOTFS_SIZE;

            /* Remove tuple from root, so it doesn't end up in the root FS. */
            table_set(root, sym(boot), 0);
        } else if (bootimg_path) {
            halt("kernel or boot FS not specified\n");
        }
    }

    create_filesystem(h,
                      SECTOR_SIZE,
                      infinity,
                      0, /* no read -> new fs */
                      closure(h, bwrite, out, offset),
                      label,
                      closure(h, fsc, h, out, root, target_root));

    off_t current_size = lseek(out, 0, SEEK_END);
    if (current_size < 0) {
        halt("could not get image size: %s\n", strerror(errno));
    }
    if (!img_size)
        img_size = current_size;
    img_size = pad(img_size, TFS_LOG_DEFAULT_EXTENSION_SIZE);
    if (current_size < img_size) {
        if (ftruncate(out, img_size)) {
            halt("could not set image size: %s\n", strerror(errno));
        }
    }
    if (bootimg_path != NULL)
        write_mbr(out);

    close(out);
    exit(0);
}
