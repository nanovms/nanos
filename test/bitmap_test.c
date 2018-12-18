#include <runtime.h>
#include <stdlib.h>
#include <bitmap.h>


boolean bitmap_test() {
    bitmap b;
    u64 bit = bitmap_alloc(b, 0);
    msg_debug("bitmap test passed.");
    return true;
}

int main(int argc, char **argv)
{
    if(bitmap_test())
        exit(EXIT_SUCCESS);
    else 
        exit(EXIT_FAILURE);
}
