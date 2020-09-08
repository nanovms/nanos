/* tests for mmap, munmap, mremap, and mincore */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

/* for sha */
#include <runtime.h>

#define handle_err(s) do { perror(s); exit(EXIT_FAILURE);} while(0)

/** Basic and intensive problem sizes **/
typedef struct {
    struct {
        unsigned long nr_mmaps;
        unsigned long alloc_at_a_time;
    } mmap;

    struct {
        unsigned long init_size;
        unsigned long end_size;
        unsigned long move_inc;
        unsigned long nr_incs;
        unsigned long nr_mmaps;
    } mremap;
} problem_size_t;

static problem_size_t problem_size_basic = {
    .mmap = {
        .nr_mmaps = 300,
        .alloc_at_a_time = 15
    },

    .mremap = {
        .init_size = (1ULL << 12),
        .end_size  = (1ULL << 25),
        .move_inc  = (1ULL << 20),
        .nr_incs   = (1ULL << 5),
        .nr_mmaps  = (1ULL << 9)
    }
};

static problem_size_t problem_size_intensive = {
    .mmap = {
        .nr_mmaps = 3000,
        .alloc_at_a_time = 150
    },

    .mremap = {
        .init_size = (1ULL << 12),
        .end_size  = (1ULL << 31),
        .move_inc  = (1ULL << 21),
        .nr_incs   = (1ULL << 10),
        .nr_mmaps  = (1ULL << 9)
    }
};

static problem_size_t * problem_size;

#define __mmap_NR_MMAPS         problem_size->mmap.nr_mmaps
#define __mmap_ALLOC_AT_A_TIME  problem_size->mmap.alloc_at_a_time
#define __mremap_INIT_SIZE      problem_size->mremap.init_size
#define __mremap_END_SIZE       problem_size->mremap.end_size
#define __mremap_MOVE_INC       problem_size->mremap.move_inc
#define __mremap_NR_INCS        problem_size->mremap.nr_incs
#define __mremap_NR_MMAPS       problem_size->mremap.nr_mmaps
/** end problem size stuff **/


typedef struct {
    void * addr;
    unsigned long size;
} mmap_t;

/* round up to nearest page address */
#define round_up_page(addr) \
        (((unsigned long)addr + (PAGESIZE-1)) & ~((PAGESIZE-1)))

#define round_down_page(addr) \
        ((unsigned long)addr & ~(PAGESIZE - 1)) 

static char zero_data[PAGESIZE] = {0};
static char landing_pad[PAGESIZE*2];

/* 
 * Generate random power of 2 between 1B and 2GB
 */
#define MIN_SHIFT 1
#define MAX_SHIFT 31
static inline unsigned long gen_random_size(void)
{
    int shift = MIN_SHIFT + (rand() % (MAX_SHIFT-MIN_SHIFT+1));
    return (1ULL << shift);
}

static void __munmap(void * addr, unsigned long len)
{
    if (munmap(addr, len)) {
        perror("munmap failed");
        exit(EXIT_FAILURE);
    }
}

/*
 * generate a permutation of the numbers in range 0 to nr_indices-1
 */
static void permute(int * permutation, int nr_indices)
{
    int i, j, temp;

    for (i = 0; i < nr_indices; i++) 
        permutation[i] = i; 

    for (i = nr_indices - 1; i>= 0; --i) {
        j = rand() % (i + 1);

        temp = permutation[i];
        permutation[i] = permutation[j];
        permutation[j] = temp;
    }    
}

/* 
 * munmap the range in several independent 2MB calls to munmap
 * to test the kernel's heap management code
 */
static void chunked_munmap(void * addr, unsigned long size)
{
    int * permutation, i;
    int nr_pages = size >> PAGELOG;

    permutation = malloc(sizeof(int) * nr_pages);
    if (permutation == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    permute(permutation, nr_pages);

    for (i = 0; i < nr_pages; i++) {
        void * unmap_at = addr + (permutation[i] << PAGELOG);
        __munmap(unmap_at, PAGESIZE);
    }

    free(permutation);
}

static void do_munmap(void * addr, unsigned long len)
{
    if (len <= PAGESIZE_2M)
        chunked_munmap(addr, len);
    else
        __munmap(addr, len);
}

static void mmap_newfile_test(void)
{
    int fd;
    const size_t maplen = 1;
    void *addr;

    fd = open("new_file", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("new file open");
        exit(EXIT_FAILURE);
    }
    addr = mmap(NULL, maplen, PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("new file  mmap");
        exit(EXIT_FAILURE);
    }
    if (munmap(addr, maplen) < 0) {
        perror("new file  munmap");
        exit(EXIT_FAILURE);
    }
    addr = mmap(NULL, maplen, PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (addr != MAP_FAILED) {
        fprintf(stderr, "%s: could mmap non-executable file with exec access\n",
            __func__);
        exit(EXIT_FAILURE);
    } else if (errno != EACCES) {
        handle_err("exec-mmap non-executable file: unexpected error");
    }
    if (close(fd) < 0) {
        perror("new file close");
        exit(EXIT_FAILURE);
    }
}

/*
 * Test correctness of virtual memory space tracking.
 *
 * This function allocates NR_MMAPS different mmap regions. It allocates them
 * in several chunks at a time. In between chunks of allocations, it frees
 * some of the mmaps to attempt to create holes in the address space, before
 * moving on to more allocations
 */
static void sparse_anon_mmap_test(void)
{
    mmap_t * mmaps;
    int i, j, nr_freed, nr_to_free;

    mmaps = malloc(sizeof(mmap_t) * __mmap_NR_MMAPS);
    if (mmaps == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    nr_freed = 0;
    for (i = 0; i < __mmap_NR_MMAPS/__mmap_ALLOC_AT_A_TIME; i++)  {
        for (j = 0; j < __mmap_ALLOC_AT_A_TIME; j++) {
            unsigned long size = gen_random_size();
            void * addr = mmap(
                NULL, 
                size, 
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, 
                -1, 0
            );

            if (addr == MAP_FAILED) {
                perror("mmap failed");
                exit(EXIT_FAILURE);
            }

            mmaps[i*__mmap_ALLOC_AT_A_TIME + j].addr = addr;
            mmaps[i*__mmap_ALLOC_AT_A_TIME + j].size = size;
        }

        /* free some but not all of them */
        nr_to_free = rand() % (
            ((i+1) * __mmap_ALLOC_AT_A_TIME)
            - nr_freed
        );

        for (j = 0; j < nr_to_free && (nr_freed+j) < __mmap_NR_MMAPS; j++)
            do_munmap(mmaps[nr_freed + j].addr, mmaps[nr_freed + j].size); 

        nr_freed += nr_to_free;
    }

    /* free whatever's left */
    while (nr_freed < __mmap_NR_MMAPS) {
        do_munmap(mmaps[nr_freed].addr, mmaps[nr_freed].size); 
        nr_freed++;
    }

    free(mmaps);
}

static void mmap_flags_test(const char  * filename, void * target_addr,
        unsigned long size, unsigned long flags)
{
    int fd;
    ssize_t bytes;
    void * addr;
    char read_contents[PAGESIZE];

    if (!(flags & MAP_ANONYMOUS)) {
        fd = open(filename, O_RDONLY);
        if (fd < 0) {
            perror("open failed");
            exit(EXIT_FAILURE);
        }

        bytes = read(fd, read_contents, PAGESIZE);
        if (bytes < 0) {
            perror("read failed");
            exit(EXIT_FAILURE);
        }
    } else {
        fd = -1;
        bytes = size;
        memset(read_contents, 0, PAGESIZE);
    }

    addr = mmap(target_addr, bytes, PROT_READ, flags, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    if ((flags & MAP_FIXED) &&
        (addr != target_addr))
    {
        fprintf(stderr, "mmap did not honor MAP_FIXED address\n");
        exit(EXIT_FAILURE);
    }

    if (!(flags & MAP_ANONYMOUS)) {
        /* ensure the contents are copied in correctly */
        if (memcmp((const void *)read_contents, addr, bytes)) {
            fprintf(stderr, "mmap and read contents differ");
            exit(EXIT_FAILURE);
        }
    } else {
        /* mmap must fill this with zero per posix */
        if (memcmp((const void *)zero_data, addr, bytes)) {
            fprintf(stderr, "anonymous mmap mapped non-zero page contents");
            exit(EXIT_FAILURE);
        }
    }

    if (munmap(addr, bytes)) {
        perror("munmap failed");
        exit(EXIT_FAILURE);
    }

    if (!(flags & MAP_ANONYMOUS))
        close(fd);
}

typedef struct {
    char * filename;
    unsigned long flags;
} mmap_test_t;

#define NR_MMAP_TESTS 8
static mmap_test_t tests[] = {
    {NULL, MAP_ANONYMOUS|MAP_PRIVATE},
    {NULL, MAP_ANONYMOUS|MAP_SHARED},
    {NULL, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED},
    {NULL, MAP_ANONYMOUS|MAP_SHARED|MAP_FIXED},
    {"infile", MAP_PRIVATE},
    {"infile", MAP_SHARED},
    {"infile", MAP_PRIVATE|MAP_FIXED},
    {"infile", MAP_SHARED|MAP_FIXED},
};

#define strncat_pretty(str, _cat, len) \
    if (str[0] != 0) {\
        strncat(str, "|"_cat, len);\
    } else {\
        strncat(str, _cat, len);\
    }

static void mmap_flags_to_str(char * str, unsigned long str_len, 
        unsigned long flags)
{
    memset(str, 0, str_len);

    if (flags & MAP_ANONYMOUS) {
        strncat_pretty(str, "MAP_ANONYMOUS", str_len);
    }
        
    if (flags & MAP_PRIVATE) {
        strncat_pretty(str, "MAP_PRIVATE", str_len);
    }

    if (flags & MAP_SHARED) {
        strncat_pretty(str, "MAP_SHARED", str_len);
    }

    if (flags & MAP_FIXED) {
        strncat_pretty(str, "MAP_FIXED", str_len);
    }
}

/* This used to be 32GB, which would not pass under Linux... */
#define LARGE_MMAP_SIZE (4ull << 30)

static void mmap_test(void)
{
    int seed, i;

    printf("** starting mmap tests\n");

    mmap_newfile_test();

    printf("  performing large mmap...\n");
    void * map_addr = mmap(NULL, LARGE_MMAP_SIZE, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    printf("  and unmap...\n");
    if (munmap(map_addr, LARGE_MMAP_SIZE)) {
        perror("munmap failed");
        exit(EXIT_FAILURE);
    }

    map_addr = mmap(NULL, LARGE_MMAP_SIZE, PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr != MAP_FAILED) {
        fprintf(stderr, "%s: could set up anonymous mapping with exec access\n",
            __func__);
        exit(EXIT_FAILURE);
    }

    srand(1);
    printf("  performing sparse_anon_mmap_test with seed=1...\n");
    sparse_anon_mmap_test();

    seed = time(NULL);
    srand(seed);
    printf("  performing sparse_anon_mmap_test with seed=%d...\n", seed);
    sparse_anon_mmap_test();

    for (i = 0; i < NR_MMAP_TESTS; i++) {
        char str[64];
        void * mmap_addr;
        unsigned long size;

        if (tests[i].flags & MAP_FIXED)
            mmap_addr = (void *)round_up_page(landing_pad); 
        else
            mmap_addr = NULL;

        if (tests[i].flags & MAP_ANONYMOUS)
            size = PAGESIZE;
        else
            size = 0;

        mmap_flags_to_str(str, 64, tests[i].flags);
        printf("  performing mmap_flag_test(%s)...\n", str);
        mmap_flags_test(tests[i].filename, mmap_addr, size, tests[i].flags);
    }

    printf("  performing munmap test...\n");
    {
        void * mmap_addr;

        mmap_addr = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (mmap_addr == MAP_FAILED) {
            perror("mmap failed");
            exit(EXIT_FAILURE);
        }
        
        if (munmap(mmap_addr, PAGESIZE)) {
            perror("munmap failed");
            exit(EXIT_FAILURE);
        }
    }

    printf("** all mmap tests passed\n");

}

static inline bool check_mincore_vec(uint8_t * vec, uint8_t * expected, int nr_pages)
{
    int i;
    for (i = 0; i < nr_pages; i++)
        if (vec[i] != expected[i])
            return false;
    return true;
}

/*
 * XXX: currently, mincore never returns -ENOMEM, but it does
 * set the vector entries to 0 for non-mapped memory
 */
static void __mincore(void * addr, unsigned long length, uint8_t * vec, 
        uint8_t * expected)
{
    int ret;

    ret = mincore(addr, length, vec);
    if (ret) {
        perror("mincore failed");
        exit(EXIT_FAILURE);
    }

    if (!check_mincore_vec(vec, expected, (length >> PAGELOG))) {
        fprintf(stderr, "mincore did not set vector entries correctly\n");
        exit(EXIT_FAILURE);
    }
}

static void mincore_test(void)
{
    uint8_t * vec, * expected;
    void * addr;

    printf("** starting mincore tests\n");

    vec = malloc(sizeof(uint8_t));
    if (vec == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    expected = malloc(sizeof(uint8_t));
    if (expected == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    /* test something on the stack */
    expected[0] = 1;
    addr = (void *)round_down_page(&vec);
    printf("  performing mincore on stack address (0x%lx)...\n", 
        (unsigned long)addr);
    __mincore(addr, PAGESIZE, vec, expected);

    /* test something on the heap */
    addr = (void *)round_down_page(vec);
    printf("  performing mincore on heap address (0x%lx)...\n",
        (unsigned long)addr);
    __mincore(addr, PAGESIZE, vec, expected);

    /* test initialized global */
    addr = (void *)round_down_page(zero_data);
    printf("  performing mincore on initialized globals (0x%lx)...\n",
        (unsigned long)addr);
    __mincore(addr, PAGESIZE, vec, expected);

    /* test something recently mmap'd/munmap'd */
    {
        addr = mmap(NULL, PAGESIZE, PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
                -1, 0);
        if (addr == MAP_FAILED) {
            perror("mmap failed");
            exit(EXIT_FAILURE);
        }

        /* demand paged --- not in core */
        expected[0] = 0;
        printf("  performing mincore on anonymous mmap (0x%lx)...\n",
            (unsigned long)addr);
        __mincore(addr, PAGESIZE, vec, expected);

        /* page it in */
        memset(addr, 0, PAGESIZE);
        expected[0] = 1;
        __mincore(addr, PAGESIZE, vec, expected);

        /* free it */
        __munmap(addr, PAGESIZE);

        /* mincore should fail now */
        if (mincore(addr, PAGESIZE, vec) == 0) {
            fprintf(stderr, "mincore succeeded when it should have failed\n");
            exit(EXIT_FAILURE);
        }

        __munmap(addr, PAGESIZE);
    }

    free(vec);
    free(expected);

    /* test a sparsely paged anonymous mmap */
    {
        int i = 0;

        vec = malloc(sizeof(uint8_t) * 512);
        if (vec == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }

        expected = malloc(sizeof(uint8_t) * 512);
        if (expected == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }

        addr = mmap(NULL, PAGESIZE*512, PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
                -1, 0);
        if (addr == MAP_FAILED) {
            perror("mmap failed");
            exit(EXIT_FAILURE);
        }

        for (i = 0; i < 512; i++) {
            if (i % 5 == 0) {
                memset(addr + (i << PAGELOG), 0, PAGESIZE);
                expected [i] = 1;
            } else {
                expected[i] = 0;
            }
        }

        printf("  performing mincore on sparsely paged anonymous mmap (0x%lx)...\n",
            (unsigned long)addr);
        __mincore(addr, PAGESIZE*512, vec, expected);

        __munmap(addr, PAGESIZE*512);
    }

    free(vec);
    free(expected);

    printf("** all mincore tests passed\n"); 
}

/*
 * mremap tests
 */
void mremap_test(void)
{
    void * map_addr, * tmp;
    unsigned long map_size;
    mmap_t * mmaps;
    uint8_t * vec;
    int i;

    printf("** starting mremap tests\n");

    map_addr = mmap(NULL, __mremap_INIT_SIZE, PROT_READ|PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    /* ensure that MREMAP_MAYMOVE is needed and MREMAP_FIXED is invalid */
    {
        tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE*2, 0);
        if (tmp != MAP_FAILED) {
            fprintf(stderr, "mremap succeeded without MREMAP_MAYMOVE??\n");
            exit(EXIT_FAILURE);
        }

        /* Disabling this check for linux parity test... */
#if 0
        tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE*2, 
                MREMAP_MAYMOVE | MREMAP_FIXED, map_addr+PAGESIZE);
        if (tmp != MAP_FAILED) {
            fprintf(stderr, "mremap succeeded with MREMAP_FIXED??\n");
            exit(EXIT_FAILURE);
        }
#endif
    }

    /*
     * allocate a bunch of mmaps to create a fragmented address space
     */
    mmaps = malloc(sizeof(mmap_t) * __mremap_NR_MMAPS);
    if (mmaps == NULL) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < __mremap_NR_MMAPS; i++) {
        unsigned long size = gen_random_size();
        tmp = mmap(
            NULL, 
            size, 
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, 
            -1, 0
        );

        if (tmp == MAP_FAILED) {
            perror("mmap failed");
            exit(EXIT_FAILURE);
        }

        mmaps[i].addr = tmp;
        mmaps[i].size = size;
    }

    vec = malloc(sizeof(uint8_t) * ((1ULL << MAX_SHIFT) >> PAGELOG)); 
    if (vec == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    /* now, remap the inital mmap a bunch of times */ 
    map_size = __mremap_INIT_SIZE;
    for (i = 0; i < __mremap_NR_INCS; i++) {
        /* round new_size to the next largest MREMAP_MOVE_INC boundary */
        unsigned long new_size = 
                (i == 0) ? __mremap_MOVE_INC : map_size+__mremap_MOVE_INC;

        tmp = mremap(map_addr, map_size, new_size, MREMAP_MAYMOVE, (void *)(unsigned long)i);
        if (tmp == MAP_FAILED) {
            perror("mremap failed");
            exit(EXIT_FAILURE);
        }

        map_addr = tmp;
        map_size = new_size;
    }

    free(vec);
    printf("** all mremap tests passed\n");
}

void mprotect_test(void)
{
    u8 *addr;
    int ret;

    if (mprotect(0, PAGESIZE, PROT_READ) == 0) {
        fprintf(stderr, "%s: could enable read access to zero page\n",
            __func__);
        exit(EXIT_FAILURE);
    } else if (errno != ENOMEM) {
        handle_err("mprotect() to zero page: unexpected error");
    }

    addr = mmap(NULL, 5 * PAGESIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        handle_err("mprotect test: mmap");

    /* To test that mprotect() touches the supplied address range only, remove
     * write access to some pages and then write to neighboring pages. */
    ret = mprotect(addr, PAGESIZE, PROT_NONE);
    if (ret < 0)
        handle_err("mprotect 1");
    addr[PAGESIZE] = 0;
    ret = mprotect(addr + 2 * PAGESIZE, PAGESIZE, PROT_NONE);
    if (ret < 0)
        handle_err("mprotect 2");
    addr[2 * PAGESIZE - 1] = 0;
    addr[3 * PAGESIZE] = 0;
    ret = mprotect(addr + 4 * PAGESIZE, PAGESIZE, PROT_NONE);
    if (ret < 0)
        handle_err("mprotect 3");
    addr[4 * PAGESIZE - 1] = 0;

    if (mprotect(addr, PAGESIZE, PROT_EXEC) == 0) {
        fprintf(stderr, "%s: could enable exec access on anonymous mapping\n",
            __func__);
        exit(EXIT_FAILURE);
    } else if (errno != EACCES) {
        handle_err("mprotect(PROT_EXEC): unexpected error");
    }

    __munmap(addr, 5 * PAGESIZE);
}

const unsigned char test_sha[2][32] = {
    { 0xca, 0xde, 0xc7, 0x27, 0x1e, 0xaa, 0xd4, 0xc6,
      0x85, 0xa9, 0xc2, 0xc0, 0x57, 0x86, 0xf8, 0x12,
      0xf5, 0x9c, 0xb1, 0xa5, 0xd4, 0xaf, 0x36, 0xe5,
      0x99, 0x1e, 0xd7, 0xf9, 0xa7, 0x57, 0x74, 0x59 },
    { 0xa6, 0x74, 0x1f, 0xae, 0xe2, 0x29, 0x45, 0xb7,
      0x0e, 0x17, 0x9d, 0xa3, 0xe3, 0x27, 0xf6, 0x45,
      0xf2, 0x71, 0xb0, 0xc5, 0xef, 0x5c, 0xf6, 0xaa,
      0x80, 0x9a, 0x0d, 0x33, 0x72, 0x3f, 0xec, 0x2d } };

#define WRITE_STRESS_FILESIZE (10ull << 20)
#define WRITE_STRESS_ITERATIONS WRITE_STRESS_FILESIZE
static void filebacked_test(heap h)
{
    int fd, rv;

    printf("** starting file-backed tests\n");
    fd = open("mapfile", O_RDWR);
    if (fd < 0)
        handle_err("open");

    /* second page (to avoid readahead, if we implement it) */
    void *p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, fd, PAGESIZE);
    if (p == (void *)-1ull)
        handle_err("mmap mapfile, second page");
    buffer b = alloca_wrap_buffer(p, PAGESIZE);
    buffer test = alloca_wrap_buffer(test_sha[1], 32);
    buffer sha = allocate_buffer(h, 32);
    sha256(sha, b);
    munmap(p, PAGESIZE);
    if (!buffer_compare(sha, test)) {
        rprintf("   sha mismatch for faulted page: %X\n", sha);
        close(fd);
        exit(EXIT_FAILURE);
    }
    printf("** faulted page sum matched, start kernel fault test\n");

    int out = open("foofile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (out < 0)
        handle_err("open 2");

    rv = ftruncate(out, PAGESIZE);
    if (rv < 0)
        handle_err("ftruncate for foofile");

    /* map first page of mapfile */
    p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        handle_err("mmap mapfile, first page");

    /* induce kernel page fault by writing from mmaped area */
    rv = write(out, p, PAGESIZE);
    if (rv < 0)
        handle_err("write");
    if (rv < PAGESIZE)
        printf("   short write: %d\n", rv);
    munmap(p, PAGESIZE);
    close(out);
    close(fd);

    /* verify content - this should already be in the cache
       (tests fault "direct" return) */
    printf("** faulting write complete, checking contents\n");
    fd = open("foofile", O_RDWR);
    if (fd < 0)
        handle_err("open foofile for re-read");
    p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        handle_err("mmap foofile");
    b = alloca_wrap_buffer(p, PAGESIZE);
    test = alloca_wrap_buffer(test_sha[0], 32);
    buffer_clear(sha);
    sha256(sha, b);
    munmap(p, PAGESIZE);
    close(fd);
    if (!buffer_compare(sha, test)) {
        rprintf("   sha mismatch for faulted page 2: %X\n", sha);
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("** written page sum matched, starting shared map (write) test\n");
    fd = open("barfile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
        handle_err("open barfile");
    rv = ftruncate(fd, PAGESIZE);
    if (rv < 0)
        handle_err("ftruncate for barfile");
    p = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == (void *)-1ull)
        handle_err("mmap barfile");
    void *p2 = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p2 == (void *)-1ull)
        handle_err("mmap barfile 2");
    for (int i = 0; i < PAGESIZE; i++)
        *(unsigned char *)(p + i) = i % 256;
    buffer_clear(sha);
    b = alloca_wrap_buffer(p, PAGESIZE);
    buffer b2 = alloca_wrap_buffer(p2, PAGESIZE);
    if (!buffer_compare(b, b2)) {
        printf("   fail: content of secondary shared mmap doesn't match primary\n");
        exit(EXIT_FAILURE);
    }
    printf("** contents of secondary shared mapping matches primary, calling msync\n");

    /* test invalid flags */
    if (msync(p, PAGESIZE, MS_SYNC | MS_ASYNC) == 0 || errno != EINVAL) {
        printf("   msync: should have failed with EINVAL\n");
        exit(EXIT_FAILURE);
    }

    if (msync(p, PAGESIZE, MS_SYNC) < 0)
        handle_err("msync");
    sha256(sha, b);
    munmap(p, PAGESIZE);
    munmap(p2, PAGESIZE);

    /* TODO: need a way to invalidate some or all of the cache to
       re-read and test barfile contents - for now just dump sha sum
       so user can dump image and validate */
    rprintf("** wrote to barfile, sha256:\n%X", sha);
    rprintf("** testing MAP_PRIVATE maps\n");

    p = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        handle_err("mmap barfile 3");
    p2 = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p2 == (void *)-1ull)
        handle_err("mmap barfile 4");

    if (memcmp(p, p2, PAGESIZE)) {
        printf("   mismatch comparing two maps of same file; should be identical\n");
        exit(EXIT_FAILURE);
    }

    (*(unsigned char *)p2)++;

    if (!memcmp(p, p2, PAGESIZE)) {
        printf("   maps identical after write to one; should differ\n");
        exit(EXIT_FAILURE);
    }

    munmap(p, PAGESIZE);
    p = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        handle_err("mmap barfile 5");

    if (!memcmp(p, p2, PAGESIZE)) {
        printf("   maps identical after re-mapping unmodified one; should differ\n");
        exit(EXIT_FAILURE);
    }

    munmap(p, PAGESIZE);
    munmap(p2, PAGESIZE);
    close(fd);

    printf("** passed, starting MAP_SHARED write stress test\n");
    fd = open("bazfile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
        handle_err("open bazfile");
    rv = ftruncate(fd, WRITE_STRESS_FILESIZE);
    if (rv < 0)
        handle_err("ftruncate for bazfile");
    p = mmap(NULL, WRITE_STRESS_FILESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == (void *)-1ull)
        handle_err("mmap bazfile");

    for (int i = 0; i < WRITE_STRESS_ITERATIONS; i++) {
        unsigned char *q = p + (rand() % WRITE_STRESS_FILESIZE);
        *q = rand() % 256;
    }
    printf("** wrote test pattern, calling msync\n");
    if (msync(p, WRITE_STRESS_FILESIZE, MS_SYNC) < 0)
        handle_err("msync");

    b = alloca_wrap_buffer(p, WRITE_STRESS_FILESIZE);
    buffer_clear(sha);
    sha256(sha, b);
    rprintf("** bazfile sha256:\n%X", sha);
    munmap(p, WRITE_STRESS_FILESIZE);
    close(fd);

    printf("** testing partial unmaps (vmap edits)\n");
    fd = open("unmapme", O_RDONLY);
    if (fd < 0)
        handle_err("open unmapme");
    p = mmap(NULL, PAGESIZE * 5, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        handle_err("mmap unmapme");

    printf("   offset unmap (head remain)\n");
    munmap(p + (PAGESIZE * 4), PAGESIZE);

    printf("   unmap at start (tail remain)\n");
    (void)*((volatile unsigned long *)p); /* induce offset_page computation bug */
    munmap(p, PAGESIZE);

    printf("   unmap in middle (head and tail remain)\n");
    munmap(p + (PAGESIZE * 2), PAGESIZE);

    printf("   unmap of remaining, isolated pages (neither head nor tail)\n");
    munmap(p + PAGESIZE, PAGESIZE);
    munmap(p + (PAGESIZE * 3), PAGESIZE);
    close(fd);

    fd = open("mapfile", O_RDONLY);
    if (fd < 0)
        handle_err("open read-only file");
    if (mmap(NULL, PAGESIZE, PROT_WRITE, MAP_SHARED, fd, 0) != MAP_FAILED) {
        fprintf(stderr, "%s: could mmap read-only file with write access\n",
            __func__);
        exit(EXIT_FAILURE);
    }
    p = mmap(NULL, PAGESIZE, PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED)
        handle_err("set up private mmap with read-only file");
    __munmap(p, PAGESIZE);
    if (close(fd) < 0)
        handle_err("close read-only file");

    printf("** all file-backed tests passed\n");
}

static volatile int expect_sigbus = 0;
static sigjmp_buf sjb;

static void handle_sigbus(int sig, siginfo_t *si, void *ucontext)
{
    printf("** received %s: sig %d, si_errno %d, si_code %d, addr 0x%lx\n",
           strsignal(sig), sig, si->si_errno, si->si_code, (unsigned long)si->si_addr);
    if (!expect_sigbus) {
        printf("  not expected; test failed\n");
        exit(EXIT_FAILURE);
    }
    if (sig != SIGBUS || si->si_code != BUS_ADRERR) {
       printf("  unexpected signal or error code; test failed\n");
        exit(EXIT_FAILURE);
    }
    siglongjmp(sjb, 1);
}

static void filebacked_sigbus_test(void)
{
    printf("** starting mmap SIGBUS test\n");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handle_sigbus;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGBUS, &sa, 0);
    if (rv < 0)
        handle_err("sigaction");

    int out = open("busfile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (out < 0)
        handle_err("open for busfile");

    printf("** truncate file to two pages\n");
    rv = ftruncate(out, PAGESIZE * 2);
    if (rv < 0)
        handle_err("ftruncate for busfile");

    void *p = mmap(NULL, PAGESIZE * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE, out, 0);
    if (p == (void *)-1ull)
        handle_err("mmap busfile");

    printf("** write to both pages (should not cause fault)\n");
    expect_sigbus = 0;
    *(unsigned long *)p = 0;
    *(unsigned long *)(p + PAGESIZE) = 0;

    printf("** truncate to one page and write first page\n");
    rv = ftruncate(out, PAGESIZE);
    if (rv < 0)
        handle_err("ftruncate for busfile 2");

    *(unsigned long *)p = 0;
    printf("** write to second page (should cause SIGBUS)\n");
    if (sigsetjmp(sjb, 1)) {
        printf("** SIGBUS test passed\n");
        munmap(p, PAGESIZE);
        close(out);
    } else {
        expect_sigbus = 1;
        *(unsigned long *)(p + PAGESIZE) = 0;
        printf("** failed; map access should have caused SIGBUS\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char * argv[])
{
    /*
     * Set default problem size to basic
     * XXX: change if/when we determine the subsystem should handle the
     * intensive cases 
     */
    problem_size = &problem_size_basic;

    if (argc == 2) {
        if (strcmp(argv[1], "intensive") == 0)
            problem_size = &problem_size_intensive;
    }

    /* flush printfs immediately */
    setbuf(stdout, NULL);

    mmap_test();
    mincore_test();
    mremap_test();
    mprotect_test();
    filebacked_test(init_process_runtime());
    filebacked_sigbus_test();

    printf("\n**** all tests passed ****\n");

    exit(EXIT_SUCCESS);
}
