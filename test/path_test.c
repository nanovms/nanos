#include <runtime.h>
#include <path.h>
#include <buffer.h>
#include <unistd.h>
//#include <stdlib.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#include <stdio.h>
#include <string.h>

int
check(heap h, char *cwd, char *real, char *expected)
{
    if (strcmp(canonicalize_path(h,
                    wrap_buffer_cstring(h, cwd),
                    wrap_buffer_cstring(h, real)), expected) != 0) {
        printf("ERR: cwd: [%s] real: [%s] vs expected [%s]\n",
                    cwd, real, expected);
        return 1;
    }

    printf("OK: [%s] && [%s] => [%s]\n",
                cwd, real, expected);

    return 0;
}

int
test_noop(heap h)
{
    int ret = 0;

    ret |= check(h, "/", "/usr/src/dragonfly", "/usr/src/dragonfly");
    ret |= check(h, "/", "/", "/");

    return ret;
}

int
test_current_directory(heap h)
{
    int ret = 0;

    ret |= check(h, "/", "/usr/src/dragonfly/.", "/usr/src/dragonfly");
    ret |= check(h, "/", "/.", "/");
    ret |= check(h, "/", "/./././././.", "/");
    ret |= check(h, "/home/nanovms", ".", "/home/nanovms");
    ret |= check(h, "/home/nanovms/", "./src", "/home/nanovms/src");

    return ret;
}

int
test_up_directory(heap h)
{
    int ret = 0;

    ret |= check(h, "/", "..", "/");
    ret |= check(h, "/", "../usr/src/", "/usr/src");
    ret |= check(h, "/", ".././", "/");
    ret |= check(h, "/home/nanovms", "..", "/home");
    ret |= check(h, "/home/nanovms", "../../home/user", "/home/user");

    return ret;
}

int
main(int argc, char **argv)
{
    heap h = init_process_runtime();
    int failure = 0;

    failure |= test_noop(h);
    failure |= test_current_directory(h);
    failure |= test_up_directory(h);

    if (failure) {
        printf("Test failed");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
