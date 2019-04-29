#include <unix_internal.h>

// from go/src/runtime/vdso_linux_amd64.go

void *vdso_base = (void *)0xffffffffff600000ull;

u64 vdso_gettimeofday(struct timeval *x, void *tz);

/* see linker_script */
extern void * vdso_start;
extern void * vdso_end;

void init_vdso(heap physical_pages, heap pages)
{
    map(u64_from_pointer(vdso_base), allocate_u64(physical_pages, PAGESIZE), PAGESIZE, PAGE_USER, pages);
    buffer b = alloca_wrap_buffer(vdso_base, PAGESIZE);
    b->end = 0; // sigh
    mov_32_imm(b, 0, u64_from_pointer(vdso_gettimeofday));
    jump_indirect(b, 0);

    /* allow user execution for vdso pages */
    u64 vs = u64_from_pointer(&vdso_start);
    u64 ve = u64_from_pointer(&vdso_end);
    u64 len = pad(ve - vs, PAGESIZE);
    update_map_flags(vs, len, PAGE_USER);
}

u64 __attribute__((section (".vdso"))) vdso_gettimeofday(struct timeval *x, void *tz)
{
    /* XXX a vdso-safe version of "timeval_from_time(x, now())" will
       need to be implemented... for now just fall back to the syscall */
    u64 rv;
    asm("syscall" : "=a" (rv) : "0" (SYS_gettimeofday), "D" (x), "S" (tz) : "memory");
    return rv;
}
