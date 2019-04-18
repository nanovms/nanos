#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

void foo(void)
{
    printf("foo\n");
}

void test_write_to_exec(void)
{
    unsigned long * p = (unsigned long *)&foo;
    printf("before write to exec page (addr = 0x%p)\n", p);
    *p = 0x0;
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

void test_writeprotect(void)
{
    void * p = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == (void *)-1) {
        printf("mmap fail: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("before write to read-only page\n");
    *(int*)p = 0;
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

void usage(char * progname)
{
    printf("usage: %s {execwrite|writeprotect}\n", progname);
    printf(" fault tests (should cause a page fault / protection violation):\n");
    printf(" \texecwrite: test writing to an executable page (should fail)\n");
    printf(" \twriteprotect: test writing to a read-only page\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char * argv[])
{
    setbuf(stdout, NULL);
    if (argc == 2) {
        if (!strcmp(argv[1], "execwrite"))
            test_write_to_exec();
        else if(!strcmp(argv[1], "writeprotect"))
            test_writeprotect();
        else
            usage(argv[0]);
    } else {
        usage(argv[0]);
    }
    return EXIT_SUCCESS;
}
