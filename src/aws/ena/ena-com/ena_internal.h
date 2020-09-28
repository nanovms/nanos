#ifndef ENA_INTERNAL_H
#define ENA_INTERNAL_H


#define PCI_BUSMAX  255 /* highest supported bus number */
#define PCI_SLOTMAX 31  /* highest supported slot number */
#define PCI_FUNCMAX 7   /* highest supported function number */

#define PCI_RID_BUS_SHIFT   8
#define PCI_RID_SLOT_SHIFT  3
#define PCI_RID_FUNC_SHIFT  0

#define PCI_RID(bus, slot, func) \
    ((((bus) & PCI_BUSMAX) << PCI_RID_BUS_SHIFT) | \
    (((slot) & PCI_SLOTMAX) << PCI_RID_SLOT_SHIFT) | \
    (((func) & PCI_FUNCMAX) << PCI_RID_FUNC_SHIFT))

#define PCI_GET_RID(dev)    PCI_RID(dev->bus, dev->slot, dev->function)

#include <atomic.h>

// TODO: bitset.h?

/*
 * Whether expr is both constant and true.  Result is itself constant.
 * Used to enable optimizations for sets with a known small size.
 */
#define __constexpr_cond(expr)  (__builtin_constant_p((expr)) && (expr))

#define __bitset_mask(_s, n)                        \
    (1UL << (__constexpr_cond(__bitset_words((_s)) == 1) ?      \
        (size_t)(n) : ((n) % _BITSET_BITS)))

#define __bitset_word(_s, n)                        \
    (__constexpr_cond(__bitset_words((_s)) == 1) ?          \
     0 : ((n) / _BITSET_BITS))

/*
 * Macros addressing word and bit within it, tuned to make compiler
 * optimize cases when SETSIZE fits into single machine word.
 */
#define _BITSET_BITS        (sizeof(long) * 8)

#define __howmany(x, y) (((x) + ((y) - 1)) / (y))

#define __bitset_words(_s)  (__howmany(_s, _BITSET_BITS))

#define BITSET_DEFINE(t, _s)                        \
struct t {                              \
        long    __bits[__bitset_words((_s))];               \
}

#define BIT_ISSET(_s, n, p)                     \
    ((((p)->__bits[__bitset_word(_s, n)] & __bitset_mask((_s), (n))) != 0))

#define BIT_ZERO(_s, p) do {                        \
    size_t __i;                           \
    for (__i = 0; __i < __bitset_words((_s)); __i++)        \
        (p)->__bits[__i] = 0L;                  \
} while (0)

#define BIT_CLR_ATOMIC(_s, n, p)                    \
    atomic_clear32((volatile u32*)&(p)->__bits[__bitset_word(_s, n)], \
        __bitset_mask((_s), n))

#define BIT_SET_ATOMIC(_s, n, p)                    \
    atomic_set32((volatile u32*)&(p)->__bits[__bitset_word(_s, n)],     \
        __bitset_mask((_s), n))

typedef unsigned int u_int;

static inline u_int
bsrl(u_int mask)
{
    u_int   result;

    __asm __volatile("bsrl %1,%0" : "=r" (result) : "rm" (mask));
    return (result);
}

static inline int fls(int mask)
{
    return (mask == 0 ? mask : (int)bsrl((u_int)mask) + 1);
}

#define EIO         5       /* Input/output error */
#define ENOMEM      12      /* Cannot allocate memory */
#define EFAULT      14      /* Bad address */
#define ENODEV      19      /* Operation not supported by device */
#define EINVAL      22      /* Invalid argument */
#define ENOSPC      28      /* No space left on device */
#define EOPNOTSUPP  45      /* Operation not supported */
#define ENOBUFS     105     /* No buffer space available */
#define ETIMEDOUT   110     /* Connection timed out */

struct ena_adapter_pci {
    struct pci_dev _dev;
    pci_dev dev;

    struct pci_bar memory;
    struct pci_bar registers;

    heap contiguous;
    heap general;
};

#endif /* !(ENA_INTERNAL_H) */

