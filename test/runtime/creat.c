#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "../test_utils.h"

/* expect = 0 for success, errno otherwise */
void _creat(const char *path, int m, int expect)
{
    printf("creat(%s, 0x%x) => ", path, m);
    int r = creat(path, (mode_t) m);
    if (r < 0) {
        printf("%s\n", strerror(errno));
        if (errno != expect)
            goto fail;
    } else {
        printf("fd %d\n", r);
        if (expect)
            goto fail;
    }
    return;
  fail:
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

/* expect = 0 for file exist, -1 for dir exist, or > 0 for errno */
void check(const char *path, int expect)
{
    struct stat st;
    int rc;

    printf("stat \"%s\" => ", path);
    rc = stat(path, &st);
    if (rc < 0) {
        printf("%s\n", strerror(errno));
        if (errno != expect)
            goto fail;
    } else {
        if (S_ISDIR(st.st_mode)) {
            printf("found directory.\n");
            if (expect != -1)
                exit(EXIT_FAILURE);
        } else {
            printf("found file.\n");
            if (expect != 0)
                exit(EXIT_FAILURE);
            rc = open(path, O_CREAT | O_EXCL, 0660);
            if ((rc != -1) || (errno != EEXIST)) {
                printf("unexpected result from open(): rc %d, errno %d\n", rc, errno);
                goto fail;
            }
        }
    }
    return;
  fail:
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int fd;
    char name_too_long[NAME_MAX + 2];

    fd = creat(FAULT_ADDR, 0);
    if ((fd != -1) || (errno != EFAULT)) {
        test_error("creat() with faulting path (%d, %d)", fd, errno);
    }

    check("/creat", 0);
    _creat("/test", 0, 0);
    check("/test", 0);
    _creat("/blurb/test/deep", 0, ENOENT);
    check("/blurb/test/deep", ENOENT);

    memset(name_too_long, '-', sizeof(name_too_long) - 1);
    name_too_long[sizeof(name_too_long) - 1] = '\0';
    _creat(name_too_long, 0, ENAMETOOLONG);

    printf("test passed\n");
    return EXIT_SUCCESS;
}
