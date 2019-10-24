/* Right now we're only implementing vsyscalls, but we'll nominally
   put everything under a vdso umbrella */

#include <unix_internal.h>
#include <page.h>
#include <synth.h>

#define VSYSCALL_OFFSET_VGETTIMEOFDAY   0x000
#define VSYSCALL_OFFSET_VTIME           0x400
#define VSYSCALL_OFFSET_VGETCPU         0x800

sysreturn vsyscall_gettimeofday(struct timeval *x, void *tz);
sysreturn vsyscall_time(time_t *tloc);
sysreturn vsyscall_getcpu(u32 * cpu, u32 * node, void * tcache /* deprecated */);

/* see linker_script */
extern void * vdso_start;
extern void * vdso_end;

void init_vdso(heap physical_pages, heap pages)
{
    /* build vsyscall vectors */
    map(VSYSCALL_BASE, allocate_u64(physical_pages, PAGESIZE), PAGESIZE, PAGE_USER, pages);
    buffer b = alloca_wrap_buffer(pointer_from_u64(VSYSCALL_BASE), PAGESIZE);
    b->end = VSYSCALL_OFFSET_VGETTIMEOFDAY;
    mov_32_imm(b, 0, u64_from_pointer(vsyscall_gettimeofday));
    jump_indirect(b, 0);

    b->end = VSYSCALL_OFFSET_VTIME;
    mov_32_imm(b, 0, u64_from_pointer(vsyscall_time));
    jump_indirect(b, 0);

    b->end = VSYSCALL_OFFSET_VGETCPU;
    mov_32_imm(b, 0, u64_from_pointer(vsyscall_getcpu));
    jump_indirect(b, 0);

    /* allow user execution for vsyscall pages */
    u64 vs = u64_from_pointer(&vdso_start);
    u64 ve = u64_from_pointer(&vdso_end);
    u64 len = pad(ve - vs, PAGESIZE);
    update_map_flags(vs, len, PAGE_USER);
}

__attribute__((no_instrument_function))
sysreturn __attribute__((section (".vdso"))) vsyscall_gettimeofday(struct timeval *x, void *tz)
{
    /* XXX a vdso-safe version of "timeval_from_time(x, now())" will
       need to be implemented... for now just fall back to the syscall */
    sysreturn rv;
    asm("syscall" : "=a" (rv) : "0" (SYS_gettimeofday), "D" (x), "S" (tz) : "memory");
    return rv;
}

__attribute__((no_instrument_function))
sysreturn __attribute__((section (".vdso"))) vsyscall_time(time_t *tloc)
{
    sysreturn rv;
    asm("syscall" : "=a" (rv) : "0" (SYS_time), "D" (tloc) : "memory");
    return rv;
}

__attribute__((no_instrument_function))
sysreturn __attribute__((section (".vdso"))) vsyscall_getcpu(u32 * cpu, u32 * node, void * tcache /* deprecated */)
{
    if (cpu)
        *cpu = 0;
    if (node)
        *node = 0;
    return 0;
}
