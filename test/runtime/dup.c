#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "../test_utils.h"

#define DUP_FD_COUNT    60000

static void test_dup(void)
{
    test_assert((dup(-1) < 0) && (errno == EBADF));
    for (int i = 0; i < DUP_FD_COUNT; i++) {
        test_assert(dup(2) == (3 + i));
    }
    for (int i = 0; i < DUP_FD_COUNT; i++) {
        test_assert(close(3 + i) == 0);
    }
}

static void test_dup2(void)
{
    test_assert((dup2(-1, 2) < 0) && (errno == EBADF));
    test_assert(dup2(1, 2) == 2);   /* closing and then re-opening fd 2 */
    test_assert(dup2(2, 2) == 2);
    for (int i = DUP_FD_COUNT; i > 2; i--) {
        test_assert(dup2(2, i) == i);
    }
    for (int i = DUP_FD_COUNT; i > 2; i--) {
        test_assert(close(i) == 0);
    }
}

static void test_dup3(void)
{
    test_assert((dup3(2, 2, 0) < 0) && (errno == EINVAL));
    test_assert((dup3(2, 3, ~O_CLOEXEC) < 0) && (errno == EINVAL));
    test_assert(dup3(2, 3, 0) == 3);
    test_assert(close(3) == 0);
}

int main(int argc, char **argv)
{
    test_dup();
    test_dup2();
    test_dup3();
    printf("Test passed\n");
    return EXIT_SUCCESS;
}
