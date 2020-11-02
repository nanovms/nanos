#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    /* simply wait a second for async bootfs open / klib read and test */
    sleep(1);
    return EXIT_SUCCESS;
}

