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
    lseek(fd, 0, SEEK_SET);
    write(fd, str, strlen(str));
    lseek(fd, 0, SEEK_SET);

    memset(buf, 0, 256);

    read(fd, buf, 256);
    printf("new: \"%s\"\n", buf);

    close(fd);
    return 0;
}
