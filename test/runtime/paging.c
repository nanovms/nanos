#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../test_utils.h"

static long pagesize;

static void foo(void)
{
    printf("foo\n");
}

static void test_write(void * p)
{
    printf("before write to addr %p (should fault here):\n", p);
    *(int *)p = 0x0;
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

/* tests that code pages, as installed by elf loader, are read-only */
static void test_write_to_exec(void)
{
    unsigned long * p = (unsigned long *)&foo;
    printf("test write to read-only text page\n");
    test_write(p);
}

/* test read-only permissions set with an mmap */
static void test_write_to_ro(void)
{
    void * p = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == (void *)-1) {
        test_perror("mmap");
    }
    printf("test write to read-only mmapped page\n");
    test_write(p);
}

/* test no-exec protection */
static void test_exec(void * p)
{
    printf("before jump to addr %p (should fault here):\n", p);
    void (*testfn)() = p;
    testfn();
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

static void test_exec_mmap()
{
    printf("test exec in mmap without PROT_EXEC\n");
    void * p = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == (void *)-1) {
        test_perror("mmap");
    }
    test_exec(p);
}

static void test_exec_heap(void)
{
    printf("test exec in heap page\n");
    void * p = malloc(sizeof(int));
    if (!p) {
        test_error("malloc");
    }
    test_exec(p);
}

static void test_exec_stack(void)
{
    int c;
    void * p = &c;
    printf("test exec in stack page\n");
    test_exec(p);
}

static void usage(char * progname)
{
    printf("usage:\n  %s { write-exec | write-ro | exec-mmap | exec-heap | exec-stack }\n", progname);
    printf("\n    protection fault tests (these should cause a page fault / protection violation):\n");
    printf(" \twrite-exec: write to executable page\n");
    printf(" \twrite-ro: write to read-only page\n");
    printf(" \texec-mmap: exec in no-exec mmaped page\n");
    printf(" \texec-heap: exec in heap\n");
    printf(" \texec-stack: exec in stack\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char * argv[])
{
    pagesize = sysconf(_SC_PAGESIZE);
    if (argc == 2) {
        if (!strcmp(argv[1], "write-exec"))
            test_write_to_exec();
        else if(!strcmp(argv[1], "write-ro"))
            test_write_to_ro();
        else if(!strcmp(argv[1], "exec-mmap"))
            test_exec_mmap();
        else if(!strcmp(argv[1], "exec-heap"))
            test_exec_heap();
        else if(!strcmp(argv[1], "exec-stack"))
            test_exec_stack();
        else
            usage(argv[0]);
    } else {
        usage(argv[0]);
    }
    return EXIT_SUCCESS;
}
