#ifndef X86_H_
#define X86_H_

#ifdef KERNEL
extern struct x86_pv_ops {
    void (*cpuid)(u32 leaf, u32 subleaf, u32 *v);
    void (*frame_return)(u64 *f) __attribute__((noreturn));
} pv_ops;

static inline void cpuid(u32 leaf, u32 subleaf, u32 *v)
{
    pv_ops.cpuid(leaf, subleaf, v);
}
#else
#define cpuid   x86_cpuid
#endif

static inline void x86_cpuid(u32 leaf, u32 subleaf, u32 *v)
{
    asm volatile("cpuid" : "=a" (v[0]), "=b" (v[1]), "=c" (v[2]), "=d" (v[3]) :
                 "0" (leaf), "2" (subleaf));
}

void x86_frame_return(u64 *f) __attribute__((noreturn));

#endif
