#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

void _mkdir(const char *path, int m)
{
    printf("mkdir(%s, 0x%x) => ", path, m);
    int r = mkdir(path, (mode_t) m);
    printf("r = %d, errno = %d\n", r, errno);
}

void check(const char *path)
{
    struct stat st;
    int rc;

    rc = stat(path, &st);
    if (rc) {
        printf("      => \"%s\" does not exist.\n");
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        printf("     => \"%s\" is not a directory.\n");
        return;
    }
}

int main(int argc, char **argv)
{
    _mkdir("/test", 0); check("/test");
    _mkdir("/blurb/test/deep", 0);
}
