#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

static long pagesize;

void foo(void)
{
    printf("foo\n");
}

/* tests that code pages, as installed by elf loader, are read-only */
void test_write_to_exec(void)
{
    unsigned long * p = (unsigned long *)&foo;
    printf("before write to addr 0x%p in code page (should fault here):\n", p);
    *p = 0x0;
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

/* test read-only permissions set with an mmap */
void test_writeprotect(void)
{
    void * p = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == (void *)-1) {
        printf("mmap fail: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("before write to read-only page (should fault here):\n");
    *(int*)p = 0;
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

/* attempt to jump into page without PROT_EXEC */
void test_noexec(void)
{
    void * p = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == (void *)-1) {
        printf("mmap fail: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("before write to read-only page (should fault here):\n");
    void (*testfn)() = p;
    testfn();
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

void usage(char * progname)
{
    printf("usage: %s {execwrite|writeprotect}\n", progname);
    printf(" fault tests (these should cause a page fault / protection violation):\n");
    printf(" \texecwrite: test writing to an executable page\n");
    printf(" \twriteprotect: test writing to a read-only page\n");
    printf(" \tnoexec: test execution from a no-exec page\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char * argv[])
{
    setbuf(stdout, NULL);
    pagesize = sysconf(_SC_PAGESIZE);
    if (argc == 2) {
        if (!strcmp(argv[1], "execwrite"))
            test_write_to_exec();
        else if(!strcmp(argv[1], "writeprotect"))
            test_writeprotect();
        else if(!strcmp(argv[1], "noexec"))
            test_noexec();
        else
            usage(argv[0]);
    } else {
        usage(argv[0]);
    }
    return EXIT_SUCCESS;
}
