#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "../test_utils.h"

static void test_xattrs_basic(const char *path, bool run_setup, bool run_cleanup)
{
    const char *attr_name = "user.attr1";
    uint64_t attr_val;
    uint8_t attr_buf[256];
    int i;
    int fd;

    test_assert((setxattr(path, "", NULL, 0, 0) == -1) && (errno == ERANGE));
    test_assert((setxattr(path, "no_namespace", NULL, 0, 0) == -1) && (errno == EOPNOTSUPP));
    test_assert((setxattr(path, ".attr1", NULL, 0, 0) == -1) && (errno == EOPNOTSUPP));
    test_assert((setxattr(path, "user.", NULL, 0, 0) == -1) && (errno == EINVAL));

    test_assert((getxattr(path, "", &attr_val, sizeof(attr_val)) == -1) && (errno == ERANGE));
    test_assert(getxattr(path, "no_namespace", &attr_val, sizeof(attr_val)) == -1);
    test_assert(errno == EOPNOTSUPP);
    test_assert(getxattr(path, ".attr1", &attr_val, sizeof(attr_val)) == -1);
    test_assert(errno == EOPNOTSUPP);
    test_assert((getxattr(path, "user.", &attr_val, sizeof(attr_val)) == -1) && (errno == EINVAL));

    if (run_setup) {
        test_assert(setxattr(path, attr_name, NULL, 0, XATTR_REPLACE) == -1);
        test_assert(errno == ENODATA);
        test_assert((getxattr(path, attr_name, NULL, 0) == -1) && (errno == ENODATA));
        test_assert(setxattr(path, attr_name, NULL, 0, XATTR_CREATE) == 0);
        test_assert(getxattr(path, attr_name, &attr_val, sizeof(attr_val)) == 0);
    }
    test_assert((setxattr(path, attr_name, NULL, 0, XATTR_CREATE) == -1) && (errno == EEXIST));

    if (run_setup) {
        attr_val = 0xdeadbeefdeadbeefUL;
        test_assert(setxattr(path, attr_name, &attr_val, sizeof(attr_val), XATTR_REPLACE) == 0);
        attr_val = 0;
        test_assert(getxattr(path, attr_name, &attr_val, 0) == sizeof(attr_val));
        test_assert(attr_val == 0);
        test_assert(getxattr(path, attr_name, &attr_val, sizeof(attr_val)) == sizeof(attr_val));
        test_assert(attr_val == 0xdeadbeefdeadbeefUL);

        for (i = 0; i < sizeof(attr_buf); i++)
            attr_buf[i] = i;
        test_assert(setxattr(path, attr_name, attr_buf, sizeof(attr_buf), 0) == 0);
        memset(attr_buf, 0, sizeof(attr_buf));
        test_assert(getxattr(path, attr_name, attr_buf, sizeof(attr_buf)) == sizeof(attr_buf));
        for (i = 0; i < sizeof(attr_buf); i++)
            test_assert(attr_buf[i] == i);

        test_assert(setxattr(path, attr_name, attr_buf, sizeof(attr_buf) / 2, 0) == 0);
        memset(attr_buf, 0, sizeof(attr_buf));
        test_assert(getxattr(path, attr_name, attr_buf, sizeof(attr_buf)) == sizeof(attr_buf) / 2);
        for (i = 0; i < sizeof(attr_buf) / 2; i++)
            test_assert(attr_buf[i] == i);
        for (i = sizeof(attr_buf) / 2; i < sizeof(attr_buf); i++)
            test_assert(attr_buf[i] == 0);
    }

    fd = open(path, O_RDONLY);
    test_assert(fd > 0);
    if (run_setup) {
        attr_val = 0x0123456789abcdefUL;
        test_assert(fsetxattr(fd, attr_name, &attr_val, sizeof(attr_val), 0) == 0);
    }
    attr_val = 0;
    test_assert(fgetxattr(fd, attr_name, &attr_val, sizeof(attr_val)) == sizeof(attr_val));
    test_assert(attr_val == 0x0123456789abcdefUL);
    close(fd);
}

static void test_xattrs_symlink(bool run_setup, bool run_cleanup)
{
    const char *link_name = "xattr_symlink";
    const char *attr_name = "security.attr1";

    if (run_setup) {
        test_assert(symlink("nonexistent", link_name) == 0);
        test_assert((setxattr(link_name, attr_name, NULL, 0, 0) == -1) && (errno == ENOENT));
        test_assert(lsetxattr(link_name, attr_name, NULL, 0, 0) == 0);
    }
    test_assert((getxattr(link_name, attr_name, NULL, 0) == -1) && (errno == ENOENT));
    test_assert(lgetxattr(link_name, attr_name, NULL, 0) == 0);
    if (run_cleanup)
        unlink(link_name);
}

void test_xattrs(int argc, char **argv)
{
    struct option long_options[] = {
        {"no-setup",   no_argument, 0, 's'},
        {"no-cleanup", no_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    bool run_setup = true;
    bool run_cleanup = true;
    int opt;
    int option_index = 0;
    int fd;

    opterr = 0;
    while ((opt = getopt_long(argc, argv, "sc", long_options, &option_index)) != -1) {
        switch (opt) {
        case 's':
            run_setup = false;
            break;
        case 'c':
            run_cleanup = false;
            break;
        }
    }
    if (run_setup) {
        fd = creat("xattr_file", S_IRUSR | S_IWUSR);
        test_assert(fd > 0);
        close(fd);
    }
    test_xattrs_basic("xattr_file", run_setup, run_cleanup);
    if (run_cleanup)
        unlink("xattr_file");

    if (run_setup)
        test_assert(mkdir("xattr_dir", S_IRUSR | S_IWUSR) == 0);
    test_xattrs_basic("xattr_dir", run_setup, run_cleanup);
    if (run_cleanup)
        rmdir("xattr_dir");

    test_xattrs_symlink(run_setup, run_cleanup);
}
