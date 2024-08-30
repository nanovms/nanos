#include <unix_internal.h>
#include <pvclock.h>

/* see linker_script */
extern void * vvar_page;

/* auto-generated into vdso-image.c
 * contains the raw binary image of the VDSO ELF
 */
extern unsigned char vdso_raw[];

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

void init_vdso(process p)
{
    physical paddr;
    u64 vaddr, size;
    pageflags flags = pageflags_default_user();

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
        map(vaddr, paddr, size, pageflags_exec(flags));
    }

    /* map first vvar page, which contains various kernel data */
    {
        vaddr = vaddr + size;
        size = PAGESIZE;
        paddr = physical_from_virtual((void *)&vvar_page);
        assert(paddr != INVALID_PHYSICAL);
        map(vaddr, paddr, size, pageflags_noexec(flags));
    }

    /* map pvclock page */
    {
        vaddr = vaddr + size;
        size = PAGESIZE;
#ifdef __x86_64__
        paddr = pvclock_get_physaddr();
#else
        paddr = INVALID_PHYSICAL; // XXX
#endif
        if (paddr != INVALID_PHYSICAL) {
            __vdso_dat->pvclock_offset = paddr & PAGEMASK;
            map(vaddr, paddr & ~PAGEMASK, size,
                pageflags_user(pageflags_readonly(pageflags_dma())));
        }
    }

#ifdef __x86_64__
    /* init legacy vsyscall mappings */
    init_vsyscall((heap)heap_physical(get_kernel_heaps()));
#endif
}
