#include <runtime.h>
#include <x86_64.h>
#define __XEN__
typedef s8 int8_t;
typedef u8 uint8_t;
typedef u16 uint16_t;
typedef s16 int16_t;
typedef u32 uint32_t;
typedef s32 int32_t;
typedef u64 uint64_t;
typedef s64 int64_t;
#include <xen.h>
#include <xen/arch-x86/cpuid.h>

#define XEN_DEBUG
#ifdef XEN_DEBUG
#define xen_debug(x, ...) do {log_printf(" XEN", x, ##__VA_ARGS__);} while(0)
#else
#define xen_debug(x, ...)
#endif

typedef struct xen_info {
    u16 xen_major;
    u16 xen_minor;
    u32 last_leaf;
    u32 msr_base;
    u64 hypercall_page;         /* assuming identity-mapped */
} *xen_info;

static xen_info xeninfo;

void xen_detect_hypervisor(kernel_heaps kh)
{
    u32 v[4];
    xen_debug("detecting via cpuid...\n");
    cpuid(XEN_CPUID_FIRST_LEAF, 0, v);
    if (!(v[1] == XEN_CPUID_SIGNATURE_EBX &&
          v[2] == XEN_CPUID_SIGNATURE_ECX &&
          v[3] == XEN_CPUID_SIGNATURE_EDX)) {
        xen_debug("no signature match; xen not detected\n");
        return;
    }

    xen_info xi = allocate(heap_general(kh), sizeof(struct xen_info));
    assert(xi != INVALID_ADDRESS);
    xi->last_leaf = v[0];

    cpuid(XEN_CPUID_LEAF(1), 0, v);
    xi->xen_major = v[0] >> 16;
    xi->xen_minor = v[0] & MASK(16);
    xen_debug("xen version %d.%d detected\n", xi->xen_major, xi->xen_minor);

    cpuid(XEN_CPUID_LEAF(2), 0, v);
    if (v[0] != 1) {
        msg_err("xen reporting %d hypercall pages; not supported\n", v[0]);
        goto fail_dealloc;
    }
    xi->msr_base = v[1];
    xen_debug("msr base 0x%x, features 1 0x%x, features 2 0x%x\n", xi->msr_base, v[2], v[3]);

    cpuid(XEN_CPUID_LEAF(3), 0, v);
    xen_debug("leaf 4, subleaf 0: 0x%x 0x%x 0x%x 0x%x\n", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(3), 1, v);
    xen_debug("leaf 4, subleaf 1: 0x%x 0x%x 0x%x 0x%x\n", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(3), 2, v);
    xen_debug("leaf 4, subleaf 2: 0x%x 0x%x 0x%x 0x%x\n", v[0], v[1], v[2], v[3]);
    
    cpuid(XEN_CPUID_LEAF(4), 0, v);
    xen_debug("leaf 5: 0x%x 0x%x 0x%x 0x%x\n", v[0], v[1], v[2], v[3]);

    cpuid(XEN_CPUID_LEAF(5), 0, v);
    xen_debug("leaf 6: 0x%x 0x%x 0x%x 0x%x\n", v[0], v[1], v[2], v[3]);

    /* allocate and install hypercall page */
    u64 hp = allocate_u64(heap_pages(kh), PAGESIZE);
    assert(hp != INVALID_PHYSICAL);
    xen_debug("hypercall page allocated at 0x%lx\n", hp);
    xi->hypercall_page = hp;
    write_msr(xi->msr_base, hp);
    xen_debug("complete\n");
    xeninfo = xi;
    return;
  fail_dealloc:
    deallocate(heap_general(kh), xi, sizeof(struct xen_info));
}

