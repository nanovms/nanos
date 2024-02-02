#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <runtime.h>

#include "../test_utils.h"

#define SYSLOG_FILE_PATH    "var/log/syslog"

static void syslog_test_basic(void)
{
    const int total = 64 * KB;
    struct stat s;
    int fd;
    char buf[64];

    do {
        printf("01234567890123456789012345678901234567890123456789012345678901234567890123456789");
        test_assert(stat(SYSLOG_FILE_PATH, &s) == 0);
    } while (s.st_size < total);

    /* Look for the pattern output via printf() in the syslog file (which will contain kernel trace
     * messages interspersed with the printf output). */
    fd = open(SYSLOG_FILE_PATH, O_RDONLY);
    test_assert(fd > 0);
    buf[sizeof(buf) - 1] = '\0';
    while (1) {
        test_assert(read(fd, buf, sizeof(buf) - 1) == sizeof(buf) - 1);
        if (strstr(buf, "0123456789"))
            break;
    }
}

int main(int argc, char **argv)
{
    syslog_test_basic();
    return EXIT_SUCCESS;
}
