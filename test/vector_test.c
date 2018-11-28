#include <runtime.h>
#include <stdlib.h>

boolean basic_test(heap h)
{
    char * msg = "";
    vector v = allocate_vector(h, 10);

    return true;
  fail:
    deallocate_vector(v);
    msg_err("vector basic test failed: %s\n", msg);
    return false;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();

    if (!basic_test(h))
	goto fail;

    msg_debug("test passed\n");
    exit(EXIT_SUCCESS);
  fail:
    msg_err("test failed\n");
    exit(EXIT_FAILURE);
}
