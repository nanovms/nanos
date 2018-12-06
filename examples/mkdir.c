#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

void _mkdir(const char *path, int m)
{
    printf("mkdir(%s, 0x%x) => ", path, m);
    int r = mkdir(path, (mode_t) m);
    printf("r = %d, errno = %d\n", r, errno);
}

int main(int argc, char **argv)
{
    _mkdir("/test", 0);
    _mkdir("/blurb/test/deep", 0);
}
