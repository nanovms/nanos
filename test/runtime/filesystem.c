#include "../test_utils.h"

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
