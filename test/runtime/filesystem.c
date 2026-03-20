#include "../test_utils.h"

#define TEST_FUNC(name) {                               \
    extern void test_##name(int argc, char *argv[]);    \
    test_##name(argc, argv);                            \
    printf(#name " test:\tOK\n");                     \
}

int main(int argc, char **argv)
{
    TEST_FUNC(creat);
    TEST_FUNC(fadv);
    TEST_FUNC(fallocate);
    TEST_FUNC(inotify);
    TEST_FUNC(links);
    TEST_FUNC(renaming);
    TEST_FUNC(unlinking);
    TEST_FUNC(xattrs);
    return EXIT_SUCCESS;
}
