#include <unix_internal.h>

// from go/src/runtime/vdso_linux_amd64.go

void *vdso_base = (void *)0xffffffffff600000ull;

u64 vdso_gettimeofday(struct timeval *x, void *tz)
{
    timeval_from_time(x, now());
    return 0;
}

void init_vdso(heap physical_pages, heap pages)
{
    map(u64_from_pointer(vdso_base), allocate_u64(physical_pages, PAGESIZE), PAGESIZE, pages);
    buffer b = alloca_wrap_buffer(vdso_base, PAGESIZE);
    b->end = 0; // sigh
    mov_64_imm(b, 0, u64_from_pointer(vdso_gettimeofday));
    jump_indirect(b, 0);
}



