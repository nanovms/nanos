#include <runtime.h>
#include <page.h>
#include <elf64.h>

//#define BOOT_ELF_DEBUG
#ifdef BOOT_ELF_DEBUG
#define boot_elf_debug rprintf
#else
#define boot_elf_debug(...) do { } while(0)
#endif

closure_function(2, 5, boolean, kernel_elf_map,
                 buffer, b, heap, bss_heap,
                 u64, vaddr, u64, offset, u64, data_size, u64, bss_size, pageflags, flags)
{
    boot_elf_debug("%s: vaddr 0x%lx, offset 0x%lx, data_size 0x%lx, bss_size 0x%lx, flags 0x%lx\n",
                   func_ss, vaddr, offset, data_size, bss_size, flags);
    u64 map_start = vaddr & ~PAGEMASK;
    data_size += vaddr & PAGEMASK;

    u64 tail_copy = bss_size > 0 ? data_size & PAGEMASK : 0;
    if (tail_copy > 0)
        data_size -= tail_copy;
    else
        data_size = pad(data_size, PAGESIZE);

    offset &= ~PAGEMASK;
    if (data_size > 0) {
        u64 paddr = physical_from_virtual(buffer_ref(bound(b), offset));
        map(map_start, paddr, data_size, flags);
        map_start += data_size;
    }
    if (bss_size > 0) {
        u64 maplen = pad(bss_size + tail_copy, PAGESIZE);
        u64 paddr = allocate_u64(bound(bss_heap), maplen);
        if (paddr == INVALID_PHYSICAL)
            goto alloc_fail;
        map(map_start, paddr, maplen, flags);
        if (tail_copy > 0) {
            void *src = buffer_ref(bound(b), offset + data_size);
            boot_elf_debug("   tail copy at 0x%lx, %ld bytes, offset 0x%lx, from %p\n",
                           map_start, tail_copy, data_size, src);
            runtime_memcpy(pointer_from_u64(paddr), src, tail_copy);
        }
        boot_elf_debug("   zero at 0x%lx, len 0x%lx\n", map_start + tail_copy, maplen - tail_copy);
        zero(pointer_from_u64(paddr + tail_copy), maplen - tail_copy);
    }
    return true;
  alloc_fail:
    msg_err("failed to allocate kernel bss mapping\n");
    return false;
}

void *load_kernel_elf(buffer b, heap bss_heap)
{
    boot_elf_debug("%s: b %p, bss_heap %p\n", func_ss, b, bss_heap);
    return load_elf(b, 0, stack_closure(kernel_elf_map, b, bss_heap));
}
