/* tests for mmap, munmap, mremap, and mincore */

#define _GNU_SOURCE
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

/* for sha */
#include <runtime.h>

#include "../test_utils.h"

/* number of threads for multithreaded file-backed fault test */
#define MT_N_THREADS 4

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
static int test_zero_page_map;
static int exec_enabled;

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

static void timespec_sub(struct timespec *a, struct timespec *b, struct timespec *r)
{
    r->tv_sec = a->tv_sec - b->tv_sec;
    r->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (a->tv_nsec < b->tv_nsec) {
        r->tv_sec--;
        r->tv_nsec += 1000000000ull;
    }
}

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
        test_perror("munmap");
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
        test_error("malloc");
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

static void mmap_illegal_flags_check(void)
{
    void *p = mmap(NULL, 4096, PROT_NONE, MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED)
        test_error("mmap should have failed without MAP_PRIVATE, MAP_SHARED or MAP_VALIDATE");
}

/*
 * mmap and munmap a new file with appropriate permissions
 */
static void mmap_newfile_test(void)
{
    int fd;
    const size_t maplen = 1;
    void *addr;

    fd = open("new_file", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("new file open");
    }
    addr = mmap(NULL, maplen, PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        test_perror("new file mmap");
    }
    if (munmap(addr, maplen) < 0) {
        test_perror("new file munmap");
    }
    if (close(fd) < 0) {
        test_perror("new file close");
    }
}

/*
 * Try to mmap a non-executable file with exec access
 * Checks that mmap fails and sets errno to EACCES
 */
static void check_exec_perm_test(void)
{
    int fd;
    const size_t maplen = 1;
    void *addr;

    fd = open("new_file_noexec", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("new file open");
    }
    addr = mmap(NULL, maplen, PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (addr != MAP_FAILED) {
        test_error("could mmap non-executable file with exec access");
    } else if (errno != EACCES) {
        test_perror("exec-mmap non-executable file: unexpected error");
    }
    if (close(fd) < 0) {
        test_perror("new file close");
    }
}

/*
 * Validate that the zero page cannot be mapped
 */
static void check_zeropage_test(void)
{
    void *addr = mmap(0, 4096, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (test_zero_page_map) {
        if (addr == MAP_FAILED)
            test_perror("map of zero page");
    } else {
        if (addr != MAP_FAILED)
            test_error("map of zero page should have failed");
    }
}

static unsigned long do_sum(unsigned long *p)
{
    unsigned long *end = p + (4096 * 3 / 8);
    unsigned long sum = 0;
    while (p < end)
        sum += *p++;
    return sum;
}

static void vmap_merge_test(void)
{
    /* Build kernel with:
       - VMAP_PARANOIA to assert adjacent vmaps are dissimilar
       - VMAP_DEBUG to observe vmaps being split and joined
    */
    int fd = open("unmapme", O_RDONLY);
    if (fd < 0)
        test_perror("open unmapme");
    void *addr, *addr2;
    addr = mmap(NULL, 4096 * 3, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        test_perror("merge test mmap");
    }

    /* Create and fill holes at beginning, middle and end of mapping. */
    unsigned long sum = do_sum(addr);
    for (int i = 0; i < 3; i++) {
        void *p = addr + (4096 * i);
        munmap(p, 4096);

        /* Verify that a hole has been created. */
        int ret = msync(addr, 4096 * 3, MS_SYNC);
        if (!ret || (errno != ENOMEM))
            test_error("msync should have failed with ENOMEM (ret %d, err '%s')", ret,
                      strerror(errno));

        addr2 = mmap(p, 4096, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, (4096 * i));
        if (addr2 == MAP_FAILED) {
            test_perror("merge test mmap 2");
        }

        /* Verify that there are no holes. */
        ret = msync(addr, 4096 * 3, MS_SYNC);
        if (ret)
            test_perror("msync after filling a hole");

        unsigned long c = do_sum(addr);
        if (c != sum)
            test_error("checksum mismatch");
    }
    munmap(addr, 4096 * 3);
    close(fd);
}

static void hint_and_fixed_test(void)
{
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        test_perror("hint test mmap");

    /* hint without fixed should relocate */
    void *addr2 = mmap(addr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr2 == MAP_FAILED)
        test_perror("hint test mmap 2");
    if (addr2 == addr)
        test_error("hint should not have replaced existing mapping");
    munmap(addr2, 4096);

    /* fixed mapping should replace */
    *(int *)addr = 1;
    addr2 = mmap(addr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (addr2 == MAP_FAILED)
        test_perror("hint test mmap 3");
    if (addr2 != addr)
        test_error("MAP_FIXED mapping returned different address");
    if (*(int *)addr)
        test_error("re-mapped memory should be zero");
    munmap(addr2, 4096);
    munmap(addr, 4096);

    /* hint should succeed here */
    addr = mmap(addr2, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        test_perror("hint test mmap 4");
    if (addr != addr2)
        test_error("hint not taken after clearing area");
    munmap(addr, 4096);

    /* hint to unaligned address */
    addr = mmap(addr2 + 0x8, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        test_perror("unaligned hint");

#ifdef MAP_FIXED_NOREPLACE
    /* map with noreplace should fail */
    if (mmap(addr, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0)
        != MAP_FAILED)
        test_error("noreplace mmap should have failed");
    munmap(addr, 4096);
#endif

    /* unaligned fixed should fail */
    addr = mmap(addr2 + 0x8, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (addr != MAP_FAILED)
        test_error("unaligned fixed map should have failed");
    if (errno != EINVAL)
        test_error("unaligned fixed map should have returned EINVAL, not %d", errno);
}

/* This used to be 32GB, which would not pass under Linux... */
#define LARGE_MMAP_SIZE (4ull << 30)

static void large_mmap_test(void)
{
    void * map_addr = mmap(NULL, LARGE_MMAP_SIZE, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr == MAP_FAILED) {
        test_perror("mmap");
    }

    if (munmap(map_addr, LARGE_MMAP_SIZE)) {
        test_perror("munmap");
    }

    if (!exec_enabled) {
        map_addr = mmap(NULL, LARGE_MMAP_SIZE, PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map_addr != MAP_FAILED) {
            test_error("could set up anonymous mapping with exec access");
        }
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
        test_error("malloc");
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
                test_perror("mmap");
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

static void *mmap_growsdown_thread(void *stack_limit)
{
    /* Expand the stack by recursively calling this function until the stack pointer reaches a point
     * close to the limit. */
    if (__builtin_frame_address(0) >= stack_limit + PAGESIZE / 2)
        mmap_growsdown_thread(stack_limit);
    return NULL;
}

static void mmap_growsdown_test(void)
{
    const size_t guard_gap = 256 * PAGESIZE;
    struct rlimit stack_limit;
    if (getrlimit(RLIMIT_STACK, &stack_limit) < 0)
        test_perror("getrlimit");
    size_t map_len = guard_gap + stack_limit.rlim_cur;

    /* For stack of the child thread, allocate a range large enough so that the stack can grow up to
     * its limit. */
    void *addr = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    if (addr == MAP_FAILED)
        test_perror("mmap");

    /* unmap most of the stack area, leaving only a small area at the top */
    const size_t initial_stack_size =
#ifdef PTHREAD_STACK_MIN
        PTHREAD_STACK_MIN;
#else
        4 * PAGESIZE;
#endif
    munmap(addr, map_len - initial_stack_size);

    void *stack = addr + map_len - initial_stack_size;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (pthread_attr_setstack(&attr, stack, initial_stack_size))
        test_error("pthread_attr_setstack");
    pthread_t thread;
    if (pthread_create(&thread, &attr, mmap_growsdown_thread, addr + guard_gap))
        test_error("pthread_create");
    pthread_attr_destroy(&attr);
    pthread_join(thread, NULL);
    if (munmap(addr, map_len) < 0)
        test_perror("munmap");
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
            test_perror("open");
        }

        bytes = read(fd, read_contents, PAGESIZE);
        if (bytes < 0) {
            test_perror("read");
        }
    } else {
        fd = -1;
        bytes = size;
        memset(read_contents, 0, PAGESIZE);
    }

    addr = mmap(target_addr, bytes, PROT_READ, flags, fd, 0);
    if (addr == MAP_FAILED) {
        test_perror("mmap");
    }

    if ((flags & MAP_FIXED) &&
        (addr != target_addr))
    {
        test_error("mmap did not honor MAP_FIXED address");
    }

    if (!(flags & MAP_ANONYMOUS)) {
        /* ensure the contents are copied in correctly */
        if (memcmp((const void *)read_contents, addr, bytes)) {
            test_error("mmap and read contents differ");
        }
    } else {
        /* mmap must fill this with zero per posix */
        if (memcmp((const void *)zero_data, addr, bytes)) {
            test_error("anonymous mmap mapped non-zero page contents");
        }
    }

    if (munmap(addr, bytes)) {
        test_perror("munmap");
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

/*
 * Iterate through tests array and run mmap_flags_test
 */
static void all_mmap_flags_tests(void)
{
    int i;

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
}

static void munmap_test(void)
{
    u8 *mmap_addr;
    int map_size, map_boundary;

    mmap_addr = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mmap_addr == MAP_FAILED) {
        test_perror("mmap");
    }
    
    if (munmap(mmap_addr, PAGESIZE)) {
        test_perror("munmap");
    }

    /* Test splitting of block-level mappings into page-level mappings. */
    map_size = 2 * PAGESIZE_2M;
    mmap_addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    test_assert(mmap_addr != MAP_FAILED);
    map_boundary = (u8 *)pad(u64_from_pointer(mmap_addr), PAGESIZE_2M) + PAGESIZE - mmap_addr;
    mmap_addr[map_boundary - 1] = 0xaa;
    __munmap(mmap_addr + map_boundary, map_size - map_boundary);    /* mapping split */
    test_assert(mmap_addr[map_boundary - 1] == 0xaa);
    __munmap(mmap_addr, map_boundary);
}

static void mmap_test(void)
{
    int seed;

    printf("** starting mmap tests\n");
    mmap_illegal_flags_check();
    mmap_newfile_test();
    if (!exec_enabled)
        check_exec_perm_test();
    check_zeropage_test();
    vmap_merge_test();
    hint_and_fixed_test();

    printf("  performing large mmap...\n");
    large_mmap_test();

    srand(1);
    printf("  performing sparse_anon_mmap_test with seed=1...\n");
    sparse_anon_mmap_test();

    seed = time(NULL);
    srand(seed);
    printf("  performing sparse_anon_mmap_test with seed=%d...\n", seed);
    sparse_anon_mmap_test();

    mmap_growsdown_test();
    all_mmap_flags_tests();

    printf("  performing munmap test...\n");
    munmap_test();

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
        test_perror("mincore");
    }

    if (!check_mincore_vec(vec, expected, (length >> PAGELOG))) {
        test_error("mincore did not set vector entries correctly");
    }
}

static void mincore_test(void)
{
    uint8_t * vec, * expected;
    void * addr;

    printf("** starting mincore tests\n");

    vec = malloc(sizeof(uint8_t));
    if (vec == NULL) {
        test_error("malloc");
    }

    expected = malloc(sizeof(uint8_t));
    if (expected == NULL) {
        test_error("malloc");
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

    if ((mincore(addr, PAGESIZE, NULL) != -1) || (errno != EFAULT)) {
        test_error("mincore fault test");
    }

    /* test something recently mmap'd/munmap'd */
    {
        addr = mmap(NULL, PAGESIZE, PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
                -1, 0);
        if (addr == MAP_FAILED) {
            test_perror("mmap");
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
            test_error("mincore succeeded when it should have failed");
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
            test_error("malloc");
        }

        expected = malloc(sizeof(uint8_t) * 512);
        if (expected == NULL) {
            test_error("malloc");
        }

        addr = mmap(NULL, PAGESIZE*512, PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
                -1, 0);
        if (addr == MAP_FAILED) {
            test_perror("mmap");
        }
        test_assert(madvise(addr, PAGESIZE * 512, MADV_NOHUGEPAGE) == 0);

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
    void * map_addr, * new_addr, * tmp;
    unsigned long map_size;
    mmap_t * mmaps;
    uint8_t * vec;
    int i;

    printf("** starting mremap tests\n");

    map_addr = mmap(NULL, __mremap_INIT_SIZE, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr == MAP_FAILED)
        test_perror("mmap");

    /* fixed requires maymove */
    new_addr = map_addr+__mremap_INIT_SIZE;
    tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE*2,
                 MREMAP_FIXED, new_addr);
    if (tmp != MAP_FAILED)
        test_error("mremap MREMAP_FIXED succeeded without MREMAP_MAYMOVE");
    if (errno != EINVAL)
        test_error("EINVAL expected, got %d", errno);

    /* fixed mremap to same address */
    tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE*2,
                 MREMAP_FIXED | MREMAP_MAYMOVE, map_addr);
    if (tmp != MAP_FAILED)
        test_error("fixed mremap to same address should have failed");
    if (errno != EINVAL)
        test_error("EINVAL expected, got %d", errno);

    /* old_size == 0 only for shared mappings */
    tmp = mremap(map_addr, 0, __mremap_INIT_SIZE*2, MREMAP_MAYMOVE, 0);
    if (tmp != MAP_FAILED)
        test_error("old_size == 0 on private mapping should have failed");
    if (errno != EINVAL)
        test_error("EINVAL expected, got %d", errno);

    /* test move to fixed address */
    tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE,
                 MREMAP_FIXED | MREMAP_MAYMOVE, new_addr);
    if (tmp == MAP_FAILED)
        test_perror("mremap");
    if (tmp != new_addr)
        test_error("fixed mremap 1 expected at %p, got %p instead", new_addr, tmp);

    /* move it back */
    tmp = mremap(new_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE,
                 MREMAP_FIXED | MREMAP_MAYMOVE, map_addr);
    if (tmp == MAP_FAILED)
        test_perror("mremap");
    if (tmp != map_addr)
        test_error("fixed mremap 2 expected at %p, got %p instead", map_addr, tmp);

    /* test extension */
    tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE*2, 0);
    if (tmp == MAP_FAILED)
        test_perror("mremap extension");
    if (tmp != map_addr)
        test_error("extended map was moved");

    /* should not be possible to grow section of mapping */
    tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE*2, 0);
    if (tmp != MAP_FAILED)
        test_error("grow should have failed");

    /* test shrinking */
    tmp = mremap(map_addr, __mremap_INIT_SIZE*2, __mremap_INIT_SIZE, 0);
    if (tmp == MAP_FAILED)
        test_perror("mremap shrink");
    if (tmp != map_addr)
        test_error("shrunken map was moved");

    /* test same size -> nop */
    tmp = mremap(map_addr, __mremap_INIT_SIZE, __mremap_INIT_SIZE, 0);
    if (tmp == MAP_FAILED)
        test_perror("mremap same size");
    if (tmp != map_addr)
        test_error("same size moved");

    /*
     * allocate a bunch of mmaps to create a fragmented address space
     */
    mmaps = malloc(sizeof(mmap_t) * __mremap_NR_MMAPS);
    if (mmaps == NULL) {
        test_error("malloc");
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
            test_perror("mmap");
        }

        mmaps[i].addr = tmp;
        mmaps[i].size = size;
    }

    vec = malloc(sizeof(uint8_t) * ((1ULL << MAX_SHIFT) >> PAGELOG)); 
    if (vec == NULL) {
        test_error("malloc");
    }

    /* now, remap the inital mmap a bunch of times */ 
    map_size = __mremap_INIT_SIZE;
    for (i = 0; i < __mremap_NR_INCS; i++) {
        /* round new_size to the next largest MREMAP_MOVE_INC boundary */
        unsigned long new_size = 
                (i == 0) ? __mremap_MOVE_INC : map_size+__mremap_MOVE_INC;

        tmp = mremap(map_addr, map_size, new_size, MREMAP_MAYMOVE, (void *)(unsigned long)i);
        if (tmp == MAP_FAILED) {
            test_perror("mremap");
        }

        map_addr = tmp;
        map_size = new_size;
    }

    /* Test splitting of block-level mappings into page-level mappings. */
    do {
        *(u64*)(map_addr) = 0xdeadbeef;
        if (map_size > PAGESIZE)
            *(u64*)(map_addr + PAGESIZE) = 0xbeefdead;
        /* the remapping can potentially split an existing mapping */
        tmp = mremap(map_addr, PAGESIZE, 2 * PAGESIZE, MREMAP_MAYMOVE);
        test_assert(tmp != MAP_FAILED);
        test_assert(*(u64*)tmp == 0xdeadbeef);
        test_assert(munmap(tmp, 2 * PAGESIZE) == 0);
        if (map_size > PAGESIZE)
            test_assert(*(u64*)(map_addr + PAGESIZE) == 0xbeefdead);
        map_addr += PAGESIZE;
        map_size -= PAGESIZE;
    } while (map_size > 0);

    free(vec);
    printf("** all mremap tests passed\n");
}

void mprotect_test(void)
{
    u8 *addr;
    int ret;
    int map_size, map_boundary;

    printf("** starting mprotect tests\n");
    ret = mprotect(0, PAGESIZE, PROT_READ);
    if (!test_zero_page_map) {
        if (ret == 0)
            test_error("could enable read access to zero page");
        if (errno != ENOMEM)
            test_perror("mprotect() to zero page: unexpected error");
    } else {
        if (ret < 0)
            test_perror("mprotect() to zero page");
    }

    addr = mmap(NULL, 5 * PAGESIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        test_perror("mprotect test: mmap");

    /* To test merging of vmaps after a flags update, build kernel with VMAP_PARANOIA */
    ret = mprotect(addr + PAGESIZE, PAGESIZE, PROT_READ);
    if (ret < 0)
        test_perror("mprotect 1");
    ret = mprotect(addr + PAGESIZE, PAGESIZE, PROT_READ | PROT_WRITE);
    if (ret < 0)
        test_perror("mprotect 2");

    /* To test that mprotect() touches the supplied address range only, remove
     * write access to some pages and then write to neighboring pages. */
    ret = mprotect(addr, PAGESIZE, PROT_NONE);
    if (ret < 0)
        test_perror("mprotect 3");
    addr[PAGESIZE] = 0;
    ret = mprotect(addr + 2 * PAGESIZE, PAGESIZE, PROT_NONE);
    if (ret < 0)
        test_perror("mprotect 4");
    addr[2 * PAGESIZE - 1] = 0;
    addr[3 * PAGESIZE] = 0;
    ret = mprotect(addr + 4 * PAGESIZE, PAGESIZE, PROT_NONE);
    if (ret < 0)
        test_perror("mprotect 5");
    addr[4 * PAGESIZE - 1] = 0;

    if (!exec_enabled) {
        if (mprotect(addr, PAGESIZE, PROT_EXEC) == 0) {
            test_error("%s: could enable exec access on anonymous mapping",
                    __func__);
        } else if (errno != EACCES) {
            test_perror("mprotect(PROT_EXEC): unexpected error");
        }

        void *addr2 = (u8 *)round_down_page(mprotect_test);
        if (mprotect(addr2, PAGESIZE, PROT_WRITE) == 0) {
            test_error("%s: could enable write access to program code", __func__);
        } else if (errno != EACCES) {
            test_perror("mprotect(PROT_WRITE): unexpected error");
        }
    }

    __munmap(addr, 5 * PAGESIZE);

    /* Test splitting of block-level mappings into page-level mappings. */
    map_size = 2 * PAGESIZE_2M;
    addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    test_assert(addr != MAP_FAILED);
    map_boundary = (u8 *)pad(u64_from_pointer(addr), PAGESIZE_2M) + PAGESIZE - addr;
    addr[map_boundary - 1] = 0;
    test_assert(mprotect(addr + map_boundary, map_size - map_boundary, PROT_NONE) == 0);
    addr[map_boundary - 1] = 0;
    __munmap(addr, map_size);
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
        test_perror("open");

    /* second page (to avoid readahead, if we implement it) */
    void *p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, fd, PAGESIZE);
    if (p == (void *)-1ull)
        test_perror("mmap mapfile, second page");
    buffer b = alloca_wrap_buffer(p, PAGESIZE);
    buffer test = alloca_wrap_buffer(test_sha[1], 32);
    buffer sha = allocate_buffer(h, 32);
    sha256(sha, b);
    munmap(p, PAGESIZE);
    if (!buffer_compare(sha, test)) {
        msg_err("%s: sha mismatch for faulted page: %X", func_ss, sha);
        close(fd);
        exit(EXIT_FAILURE);
    }
    printf("** faulted page sum matched, start kernel fault test\n");

    int out = open("foofile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (out < 0)
        test_perror("open 2");

    rv = ftruncate(out, PAGESIZE);
    if (rv < 0)
        test_perror("ftruncate for foofile");

    /* map first page of mapfile */
    p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap mapfile, first page");

    /* induce kernel page fault by writing from mmaped area */
    rv = write(out, p, PAGESIZE);
    if (rv < 0)
        test_perror("write");
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
        test_perror("open foofile for re-read");
    p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap foofile");
    b = alloca_wrap_buffer(p, PAGESIZE);
    test = alloca_wrap_buffer(test_sha[0], 32);
    buffer_clear(sha);
    sha256(sha, b);
    munmap(p, PAGESIZE);
    close(fd);
    if (!buffer_compare(sha, test)) {
        msg_err("%s: sha mismatch for faulted page 2: %X", func_ss, sha);
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("** written page sum matched, starting shared map (write) test\n");
    fd = open("barfile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
        test_perror("open barfile");
    rv = ftruncate(fd, PAGESIZE);
    if (rv < 0)
        test_perror("ftruncate for barfile");
    p = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap barfile");
    void *p2 = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p2 == (void *)-1ull)
        test_perror("mmap barfile 2");
    for (int i = 0; i < PAGESIZE; i++)
        *(unsigned char *)(p + i) = i % 256;
    buffer_clear(sha);
    b = alloca_wrap_buffer(p, PAGESIZE);
    buffer b2 = alloca_wrap_buffer(p2, PAGESIZE);
    if (!buffer_compare(b, b2)) {
        test_error("content of secondary shared mmap doesn't match primary");
    }
    printf("** contents of secondary shared mapping matches primary, calling msync\n");

    /* test invalid flags */
    if (msync(p, PAGESIZE, MS_SYNC | MS_ASYNC) == 0 || errno != EINVAL) {
        test_error("msync should have failed with EINVAL");
    }

    if (msync(p, PAGESIZE, MS_SYNC) < 0)
        test_perror("msync");
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
        test_perror("mmap barfile 3");
    p2 = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p2 == (void *)-1ull)
        test_perror("mmap barfile 4");

    if (memcmp(p, p2, PAGESIZE)) {
        test_error("mismatch comparing two maps of same file; should be identical");
    }

    (*(unsigned char *)p2)++;

    if (!memcmp(p, p2, PAGESIZE)) {
        test_error("maps identical after write to one; should differ");
    }

    munmap(p, PAGESIZE);
    p = mmap(NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap barfile 5");

    if (!memcmp(p, p2, PAGESIZE)) {
        test_error("maps identical after re-mapping unmodified one; should differ");
    }

    munmap(p, PAGESIZE);
    munmap(p2, PAGESIZE);
    close(fd);

    printf("** passed, starting MAP_SHARED write stress test\n");
    fd = open("bazfile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
        test_perror("open bazfile");
    rv = ftruncate(fd, WRITE_STRESS_FILESIZE);
    if (rv < 0)
        test_perror("ftruncate for bazfile");
    p = mmap(NULL, WRITE_STRESS_FILESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap bazfile");

    for (int i = 0; i < WRITE_STRESS_ITERATIONS; i++) {
        unsigned char *q = p + (rand() % WRITE_STRESS_FILESIZE);
        *q = rand() % 256;
    }
    printf("** wrote test pattern, calling msync\n");
    if (msync(p, WRITE_STRESS_FILESIZE, MS_SYNC) < 0)
        test_perror("msync");

    b = alloca_wrap_buffer(p, WRITE_STRESS_FILESIZE);
    buffer_clear(sha);
    sha256(sha, b);
    rprintf("** bazfile sha256:\n%X", sha);
    munmap(p, WRITE_STRESS_FILESIZE);
    close(fd);

    printf("** testing partial unmaps (vmap edits)\n");
    fd = open("unmapme", O_RDONLY);
    if (fd < 0)
        test_perror("open unmapme");
    p = mmap(NULL, PAGESIZE * 5, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap unmapme");

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
        test_perror("open read-only file");
    if (mmap(NULL, PAGESIZE, PROT_WRITE, MAP_SHARED, fd, 0) != MAP_FAILED) {
        test_error("%s: could mmap read-only file with write access",
            __func__);
    }
    p = mmap(NULL, PAGESIZE, PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED)
        test_perror("set up private mmap with read-only file");
    __munmap(p, PAGESIZE);
    if (close(fd) < 0)
        test_perror("close read-only file");

    printf("** testing mmap with closed file descriptor\n");
    fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
        test_perror("open tmpfile");
    rv = ftruncate(fd, PAGESIZE);
    if (rv < 0)
        test_perror("ftruncate for tmpfile");
    p = mmap(NULL, PAGESIZE, PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap tmpfile");
    close(fd);
    *(uint64_t *)p = 0; /* random access to file-backed memory */
    __munmap(p, PAGESIZE);

    printf("** testing mmapped file length\n");
    fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
        test_perror("open tmpfile");
    rv = ftruncate(fd, PAGESIZE / 2);
    if (rv < 0)
        test_perror("ftruncate tmpfile");
    p = mmap(NULL, PAGESIZE, PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap tmpfile");
    *(uint64_t *)(p + PAGESIZE / 2) = 0; /* access to file-backed memory past file length */
    rv = fsync(fd);
    if (rv < 0)
        test_perror("fsync tmpfile");
    struct stat st;
    rv = fstat(fd, &st);
    if (rv < 0)
        test_perror("fstat tmpfile");
    if (st.st_size != PAGESIZE / 2) {
        test_error("file size changed to %ld following write to mmapped memory", st.st_size);
    }
    __munmap(p, PAGESIZE);
    close(fd);

    printf("** all file-backed tests passed\n");
}

struct {
    void *p;
    pthread_mutex_t mutex;
    pthread_cond_t running_cond;
    pthread_cond_t enable_cond;
    int running;
    int enable;
    int fd;
    int out_fd;
    int kern_thread;
} mt;

static void *mt_worker(void *z)
{
    int n = (int)(long)z;
    /* bump count and signal ready */
    pthread_mutex_lock(&mt.mutex);
    mt.running++;
    pthread_cond_signal(&mt.running_cond);
    pthread_mutex_unlock(&mt.mutex);

    /* wait for run condition */
    pthread_mutex_lock(&mt.mutex);
    while (!mt.enable) {
        pthread_cond_wait(&mt.enable_cond, &mt.mutex);
    }
    pthread_mutex_unlock(&mt.mutex);

    /* access page */
    if (n == mt.kern_thread) {
        /* induce kernel pagefault by writing from fault page */
        if (write(mt.out_fd, mt.p, PAGESIZE) < 0)
            test_perror("mt write");
        close(mt.out_fd);
        mt.out_fd = 0;
    } else {
        (void)*((volatile unsigned long *)mt.p);
    }
    pthread_exit(0);
}

/* This is designed to induce multiple concurrent faults for a common
   page. Without in-kernel diagnostics, this behavior will just need to be
   validated by manually running test with multiple cores and with debugs
   enabled that report such concurrency (basically anything being added to a
   pending_fault dependency list or the kern flag being set on an existing
   entry). It may also help to pick a storage driver and device that are
   particularly slow. At worst, this test will just induce no concurrency and
   pass without validating anything. */
void multithread_filebacked_test(heap h, int n_threads)
{
    printf("** starting multi-thread file-backed test\n");
    pthread_t *threads = malloc(sizeof(pthread_t) * n_threads);
    mt.fd = open("mapfile2", O_RDONLY);
    if (mt.fd < 0)
        test_perror("mt open");
    mt.out_fd = open("outfile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (mt.out_fd < 0)
        test_perror("mt create");
    if (ftruncate(mt.out_fd, PAGESIZE) < 0)
        test_perror("mt ftruncate");
    mt.p = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE, mt.fd, 0);
    if (mt.p == (void *)-1ull)
        test_perror("mmap mapfile, first page");

    mt.enable = 0;
    mt.running = 0;
    mt.kern_thread = 0;
    pthread_mutex_init(&mt.mutex, 0);
    pthread_cond_init(&mt.running_cond, 0);
    pthread_cond_init(&mt.enable_cond, 0);

    /* create worker threads that each hit the same page */
    for (int i = 0; i < n_threads; i++) {
        int r = pthread_create(threads + i, 0, mt_worker, (void*)(long)i);
        if (r != 0)
            test_error("pthread_create");
    }

    /* wait for threads to start */
    pthread_mutex_lock(&mt.mutex);
    while (mt.running < n_threads)
        pthread_cond_wait(&mt.running_cond, &mt.mutex);
    pthread_mutex_unlock(&mt.mutex);

    /* start threads */
    pthread_mutex_lock(&mt.mutex);
    mt.enable = 1;
    pthread_cond_broadcast(&mt.enable_cond);
    pthread_mutex_unlock(&mt.mutex);
    for (int i = 0; i < n_threads; i++) {
        if (pthread_join(threads[i], NULL) != 0)
            test_error("pthread_join");
    }
    munmap(mt.p, PAGESIZE);
    close(mt.fd);
}

static volatile int expect_sigbus = 0;
static sigjmp_buf sjb;

static void handle_sigbus(int sig, siginfo_t *si, void *ucontext)
{
    printf("** received %s: sig %d, si_errno %d, si_code %d, addr 0x%lx\n",
           strsignal(sig), sig, si->si_errno, si->si_code, (unsigned long)si->si_addr);
    if (!expect_sigbus) {
        test_error("not expected");
    }
    if (sig != SIGBUS || si->si_code != BUS_ADRERR) {
        test_error("unexpected signal or error code");
    }
    siglongjmp(sjb, 1);
}

#define MAP_SIZE 4096
static void check_fault_in_user_memory(void)
{
    printf("** check MAP_POPULATE\n");
    void *p = mmap(0, MAP_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p == MAP_FAILED)
        test_perror("mmap with MAP_POPULATE");
    /* TODO: actually validate this once we have something like /proc/<tid>/stat ... */
    munmap(p, MAP_SIZE);

    printf("** validate_user_memory_permissions() test\n");
    p = mmap(0, MAP_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        test_perror("mmap with prot none");
    int rv = stat("infile", p);
    if (rv != -1 || errno != EFAULT)
        test_error("stat should have failed with EFAULT (rv %d, errno %d)", rv, errno);
    munmap(p, MAP_SIZE);

    /* Check that we can handle a file-backed fault on a mapped pathname. If
       the kernel does not fault in the pathname before making a call that
       takes the filesystem lock, this will hang. */
    printf("** fault_in_user_string() test\n");
    int fd = open("testpath", O_RDONLY);
    if (fd < 0)
        test_perror("open testpath");
    p = mmap(0, MAP_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap testpath");
    rv = access(p, O_RDONLY);
    if (rv < 0)
        test_perror("access testpath map");
    munmap(p, MAP_SIZE);
    close(fd);

    /* Now attempt to write to a new file-backed mapping. Before the call to
       fault_in_user_memory() was added to stat_internal(), the page fault
       would deadlock while trying to take the filesystem lock. */
    printf("** fault_in_user_memory() test\n");
    fd = open("stattest", O_RDWR);
    if (fd < 0)
        test_perror("open stattest");
    p = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == (void *)-1ull)
        test_perror("mmap stattest");
    rv = stat("infile", p);
    if (rv < 0)
        test_perror("stat to file-backed page");
    munmap(p, MAP_SIZE);
    close(fd);
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
        test_perror("sigaction");

    int out = open("busfile", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (out < 0)
        test_perror("open for busfile");

    printf("** truncate file to two pages\n");
    rv = ftruncate(out, PAGESIZE * 2);
    if (rv < 0)
        test_perror("ftruncate for busfile");

    void *p = mmap(NULL, PAGESIZE * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE, out, 0);
    if (p == (void *)-1ull)
        test_perror("mmap busfile");

    printf("** write to both pages (should not cause fault)\n");
    expect_sigbus = 0;
    compiler_barrier();
    *(unsigned long *)p = 0;
    *(unsigned long *)(p + PAGESIZE) = 0;

    printf("** truncate to one page and write first page\n");
    rv = ftruncate(out, PAGESIZE);
    if (rv < 0)
        test_perror("ftruncate for busfile 2");

    *(unsigned long *)p = 0;
    printf("** write to second page (should cause SIGBUS)\n");
    if (sigsetjmp(sjb, 1)) {
        printf("** SIGBUS test passed\n");
        munmap(p, PAGESIZE);
        close(out);
    } else {
        expect_sigbus = 1;
        compiler_barrier();
        *(unsigned long *)(p + PAGESIZE) = 0;
        test_error("map access should have caused SIGBUS");
    }
}

static void thp_test(void)
{
    size_t map_len = 16 * MB;
    u8 *addr = mmap(NULL, map_len, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        test_perror("mmap");
    }
    test_assert(madvise(addr, map_len, MADV_HUGEPAGE) == 0);

    /* Trigger on-demand paging of different page sizes. */

    /* Split vmap into 2 adjacent vmaps with a boundary aligned to 4 KB but non-aligned to larger
     * page sizes. */
    u8 *map_boundary = pointer_from_u64((u64_from_pointer(addr + 8 * MB) & ~MASK(PAGELOG_2M)) -
                                        PAGESIZE);
    test_assert(mprotect(map_boundary, addr + map_len - map_boundary, PROT_READ) == 0);
    *(map_boundary - PAGESIZE) = 0;         /* 4KB */
    *(map_boundary - 2 * PAGESIZE) = 0;     /* 8KB */
    *(map_boundary - 4 * PAGESIZE) = 0;     /* 16KB */
    *(map_boundary - 8 * PAGESIZE) = 0;     /* 32KB */
    *(map_boundary - 16 * PAGESIZE) = 0;    /* 64KB */
    *(map_boundary - 32 * PAGESIZE) = 0;    /* 128KB */
    *(map_boundary - 64 * PAGESIZE) = 0;    /* 256KB */
    *(map_boundary - 128 * PAGESIZE) = 0;   /* 512KB */
    *(map_boundary - 256 * PAGESIZE) = 0;   /* 1MB */
    *(map_boundary - 512 * PAGESIZE) = 0;   /* 2MB */

    /* Again, make map boundary aligned to 4 KB but non-aligned to larger page sizes. */
    map_boundary += 2 * PAGESIZE;
    test_assert(mprotect(map_boundary, addr + map_len - map_boundary, PROT_WRITE) == 0);
    test_assert(mprotect(addr, map_boundary - addr, PROT_READ) == 0);
    *(map_boundary) = 0;                    /* 4KB */
    *(map_boundary + 2 * PAGESIZE) = 0;     /* 8KB */
    *(map_boundary + 4 * PAGESIZE) = 0;     /* 16KB */
    *(map_boundary + 8 * PAGESIZE) = 0;     /* 32KB */
    *(map_boundary + 16 * PAGESIZE) = 0;    /* 64KB */
    *(map_boundary + 32 * PAGESIZE) = 0;    /* 128KB */
    *(map_boundary + 64 * PAGESIZE) = 0;    /* 256KB */
    *(map_boundary + 128 * PAGESIZE) = 0;   /* 512KB */
    *(map_boundary + 256 * PAGESIZE) = 0;   /* 1MB */
    *(map_boundary + 512 * PAGESIZE) = 0;   /* 2MB */

    /* Fault-in an 8KB area straddling a 2MB boundary, then trigger on-demand paging at both sides
     * of this area, creating 1MB pages that would have been 2MB if the 8KB area had not been
     * faulted-in previously. */
    u8 *no_thp_end = map_boundary + 6 * MB;
    u8 *no_thp_start = no_thp_end - 2 * PAGESIZE;
    test_assert(madvise(no_thp_start, no_thp_end - no_thp_start, MADV_NOHUGEPAGE) == 0);
    *(no_thp_start) = 0;            /* 4KB */
    *(no_thp_start + PAGESIZE) = 0; /* 4KB */
    test_assert(madvise(no_thp_start, no_thp_end - no_thp_start, MADV_HUGEPAGE) == 0);
    *(no_thp_start - 511 * PAGESIZE) = 0;   /* 1MB */
    *(no_thp_end + 510 * PAGESIZE) = 0;   /* 1MB */

    munmap(addr, map_len);

    map_len = 512 * MB;
    struct timespec start, end, elapsed;
    test_assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    addr = mmap(NULL, map_len, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    test_assert(addr != MAP_FAILED);
    for (int i = 0; i < map_len; i += PAGESIZE) /* fault-in all mapped memory */
        addr[i] = 0;
    munmap(addr, map_len);
    test_assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    timespec_sub(&end, &start, &elapsed);
    unsigned long long ns = elapsed.tv_sec * 1000000000ull + elapsed.tv_nsec;
    printf("%s: paged %lu bytes in %ld.%.9ld seconds (%lld MB/s)\n", __func__, map_len,
           elapsed.tv_sec, elapsed.tv_nsec, (1000000000ull / MB) * map_len / ns);
}

static void madvise_test(void)
{
    size_t map_len = 2 * PAGESIZE;
    void *addr = mmap(NULL, map_len, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        test_perror("mmap");
    }
    munmap(addr, map_len / 2);
    /* madvise on (partially) unmapped address range */
    test_assert((madvise(addr, map_len, MADV_HUGEPAGE) == -1) && (errno == ENOMEM));
    munmap(addr + map_len / 2, map_len / 2);

    thp_test();
}

int main(int argc, char * argv[])
{
    /*
     * Set default problem size to basic
     * XXX: change if/when we determine the subsystem should handle the
     * intensive cases 
     */
    problem_size = &problem_size_basic;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "intensive") == 0)
            problem_size = &problem_size_intensive;
        if (strcmp(argv[i], "zeropage") == 0)
            test_zero_page_map = 1;
        if (strcmp(argv[i], "exec") == 0)
            exec_enabled = 1;
    }

    heap h = init_process_runtime();
    mmap_test();
    mincore_test();
    mremap_test();
    mprotect_test();
    filebacked_test(h);
    multithread_filebacked_test(h, MT_N_THREADS);
    filebacked_sigbus_test();
    madvise_test();
    check_fault_in_user_memory();

    printf("\n**** all tests passed ****\n");

    exit(EXIT_SUCCESS);
}
