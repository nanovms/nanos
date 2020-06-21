#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

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
        }
    }
    return;
  fail:
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    check("/creat", 0);
    _creat("/test", 0, 0);
    check("/test", 0);
    _creat("/blurb/test/deep", 0, ENOENT);
    check("/blurb/test/deep", ENOENT);
    printf("test passed\n");
    return EXIT_SUCCESS;
}
