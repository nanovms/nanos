#include <unix_internal.h>
#include <synth.h>
#include <pvclock.h>

#define VSYSCALL_OFFSET_VGETTIMEOFDAY   0x000
#define VSYSCALL_OFFSET_VTIME           0x400
#define VSYSCALL_OFFSET_VGETCPU         0x800

/* see linker_script */
extern void * vsyscall_start;
extern void * vsyscall_end;
extern void * vvar_page;

/* auto-generated into vdso-image.c
 * contains the raw binary image of the VDSO ELF
 */
extern unsigned char vdso_raw[];

/* vsyscalls are deprecated -- just provide a simple emulation layer */
VSYSCALL sysreturn
vsyscall_gettimeofday(struct timeval * tv, void * tz)
{
    return do_syscall(SYS_gettimeofday, tv, tz);
}

VSYSCALL sysreturn
vsyscall_time(time_t * t)
{
    return do_syscall(SYS_time, t, 0);
}

VSYSCALL sysreturn
vsyscall_getcpu(unsigned * cpu, unsigned * node, void * tcache)
{
    if (cpu)
        *cpu = 0;
    if (node)
        *node = 0;
    return 0;
}

/*
 * Init legacy vsyscall support
 */
void init_vsyscall(heap phys)
{
    /* build vsyscall vectors */
    u64 p = allocate_u64(phys, PAGESIZE);
    assert(p != INVALID_PHYSICAL);
    map(VSYSCALL_BASE, p, PAGESIZE, PAGE_USER);
    buffer b = alloca_wrap_buffer(pointer_from_u64(VSYSCALL_BASE), PAGESIZE);
    b->end = VSYSCALL_OFFSET_VGETTIMEOFDAY;
    mov_64_imm(b, 0, u64_from_pointer(vsyscall_gettimeofday));
    jump_indirect(b, 0);

    b->end = VSYSCALL_OFFSET_VTIME;
    mov_64_imm(b, 0, u64_from_pointer(vsyscall_time));
    jump_indirect(b, 0);

    b->end = VSYSCALL_OFFSET_VGETCPU;
    mov_64_imm(b, 0, u64_from_pointer(vsyscall_getcpu));
    jump_indirect(b, 0);

    /* allow user execution for vsyscall pages */
    u64 vs = u64_from_pointer(&vsyscall_start);
    u64 ve = u64_from_pointer(&vsyscall_end);
    u64 len = pad(ve - vs, PAGESIZE);
    update_map_flags(vs, len, PAGE_USER);
}

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

void init_vdso(process p)
{
    kernel_heaps kh;
    physical paddr;
    u64 vaddr, size;

    kh = &(p->uh->kh);

    /* sanity checks */
    assert(((unsigned long)&vvar_page & MASK(PAGELOG)) == 0);
    assert(((unsigned long)vdso_raw & MASK(PAGELOG)) == 0);

    /* map single VDSO PT_LOAD segment, which contains the raw ELF binary */
    {
        vaddr = p->vdso_base;
        assert((vdso_raw_length & PAGEMASK) == 0);
        size = vdso_raw_length;
        paddr = physical_from_virtual(vdso_raw);
        assert(paddr != INVALID_PHYSICAL);
        map(vaddr, paddr, size, PAGE_USER);
    }

    /* map first vvar page, which contains various kernel data */
    {
        vaddr = vaddr + size;
        size = PAGESIZE;
        paddr = physical_from_virtual((void *)&vvar_page);
        assert(paddr != INVALID_PHYSICAL);
        map(vaddr, paddr, size, PAGE_USER | PAGE_NO_EXEC);
    }

    /* map pvclock page */
    {
        vaddr = vaddr + size;
        size = PAGESIZE;
        paddr = pvclock_get_physaddr();
        if (paddr != INVALID_PHYSICAL) {
            __vdso_dat->pvclock_offset = paddr & PAGEMASK;
            map(vaddr, paddr & ~PAGEMASK, size, PAGE_USER | PAGE_NO_EXEC);
        }
    }

    /* init legacy vsyscall mappings */
    init_vsyscall((heap)heap_physical(kh));
}
