#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static char *str = "This seems to have worked.";
static char buf[256];

int
main(int argc, char **argv)
{
    int fd = open("/hello", O_CREAT, O_RDWR);
    read(fd, buf, 256);
    printf("original: \"%s\"\n", buf);
    write(fd, str, strlen(str));
    close(fd);

    return 0;
}
