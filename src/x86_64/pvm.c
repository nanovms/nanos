/* Pagetable-based Virtual Machine hypervisor */

#include <kernel.h>
#include "pvm.h"

#define PVM_CPUID_SIGNATURE         0x40000000
#define PVM_CPUID_VENDOR_FEATURES   0x40000002

#define KVM_SIGNATURE   "KVMKVMKVM\0\0\0"
#define PVM_SIGNATURE   0x4d5650    /* "PVM\0" */

#define MSR_PVM_LINEAR_ADDRESS_RANGE    0x4b564df0
#define MSR_PVM_VCPU_STRUCT             0x4b564df1
#define MSR_PVM_SUPERVISOR_RSP          0x4b564df2
#define MSR_PVM_EVENT_ENTRY             0x4b564df4
#define MSR_PVM_RETU_RIP                0x4b564df5
#define MSR_PVM_RETS_RIP                0x4b564df6
#define MSR_PVM_SWITCH_CR3              0x4b564df7

boolean pvm_detected;

boolean pvm_detect(void)
{
    u64 flags = read_flags();
    if (!(flags & U64_FROM_BIT(EFLAG_INTERRUPT)))
        return false;
    u64 cs;
    asm volatile("mov %%cs,%0" : "=r" (cs) : );
    if ((cs & 0x3) != 3)    /* check if CPL == 3 */
        return false;
    u32 v[4];
    pvm_cpuid(PVM_CPUID_SIGNATURE, 0, v);
    if ((v[0] < PVM_CPUID_VENDOR_FEATURES) || runtime_memcmp(&v[1], KVM_SIGNATURE, 3 * sizeof(u32)))
        return false;
    pvm_cpuid(PVM_CPUID_VENDOR_FEATURES, 0, v);
    return pvm_detected = (v[1] == PVM_SIGNATURE);
}

range pvm_get_addr_range(void)
{
    u64 addr_range = read_msr(MSR_PVM_LINEAR_ADDRESS_RANGE);
    u64 pml4_index_start = addr_range & 0x1ff;
    u64 pml4_index_end = (addr_range >> 16) & 0x1ff;
    return irange((0x1fffe00 | pml4_index_start) << PT_SHIFT_L1,
                  (0x1fffe00 | pml4_index_end) << PT_SHIFT_L1);
}

closure_func_basic(thunk, void, pvm_cpu_init)
{
    /* the PVM vCPU struct must be page-aligned */
    struct pvm_vcpu *pvm = allocate_zero((heap)heap_page_backed(get_kernel_heaps()), PAGESIZE);
    assert(pvm != INVALID_ADDRESS);

    /* PVM requires user-mode segment selectors to have the same values as used on Linux */
    pvm->user_ss = 0x2b;
    pvm->user_cs = 0x33;

    write_msr(MSR_PVM_VCPU_STRUCT, physical_from_virtual(pvm));
    cpuinfo ci = current_cpu();
    ci->m.pvm = pvm;
    write_msr(KERNEL_GS_MSR, u64_from_pointer(ci));
    u64 cr3;
    mov_from_cr("cr3", cr3);
    /* In order for the direct switching feature to be enabled (i.e. to switch between user mode and
     * supervisor mode without a VM exit), PVM requires CR3 values for the two modes to be different
     * from each other; since Nanos uses a single CR3 value, flip one bit between the user CR3 and
     * the supervisor CR3 to make them appear as different values (a CR3 value must be page-aligned,
     * so the flipped bit will not cause a different page table root to be used). */
    write_msr(MSR_PVM_SWITCH_CR3, cr3 | 1);
    extern void *pvm_event_entry;
    write_msr(MSR_PVM_EVENT_ENTRY, u64_from_pointer(&pvm_event_entry));
    extern void *pvm_retu, *pvm_rets;
    write_msr(MSR_PVM_RETU_RIP, u64_from_pointer(&pvm_retu));
    write_msr(MSR_PVM_RETS_RIP, u64_from_pointer(&pvm_rets));
    /* Configure initial stack for PVM events in user mode: the actual stack (interrupt vs
     * exception) is selected in the event handler. */
    write_msr(MSR_PVM_SUPERVISOR_RSP, u64_from_pointer(ci->m.int_stack));
}

void pvm_setup(kernel_heaps kh)
{
    thunk t = closure_func(heap_general(kh), thunk, pvm_cpu_init);
    assert(t != INVALID_ADDRESS);
    apply(t);
    register_percpu_init(t);
}

void pvm_cpuid(u32 leaf, u32 subleaf, u32 *v)
{
    asm volatile(".byte 0x0f,0x01,0x3c,0x25,0x50,0x56,0x4d,0xff,0x0f,0xa2" :
                 "=a" (v[0]), "=b" (v[1]), "=c" (v[2]), "=d" (v[3]) : "0" (leaf), "2" (subleaf));
}

void pvm_event(boolean save_frame)
{
    cpuinfo ci = current_cpu();
    struct pvm_vcpu *pvm = ci->m.pvm;
    context_frame f = get_current_context(ci)->frame;
    if (save_frame) {
        f[FRAME_RIP] = pvm->rip;
        f[FRAME_RSP] = pvm->rsp;
        f[FRAME_EFLAGS] = pvm->eflags;
        f[FRAME_RCX] = pvm->rcx;
        f[FRAME_R11] = pvm->r11;
        f[FRAME_VECTOR] = pvm->event_vector;
        f[FRAME_ERROR_CODE] = pvm->event_errcode;
    }
    u32 vector = f[FRAME_VECTOR];
    if (vector == 14)   /* page fault */
        f[FRAME_CR2] = pvm->cr2;
    void *stack = (vector < INTERRUPT_VECTOR_START) ? ci->m.exception_stack : ci->m.int_stack;
    switch_stack(stack, common_handler);
}

void pvm_syscall(context user_ctx)
{
    extern void (*syscall)(context ctx);
    cpuinfo ci = current_cpu();
    struct pvm_vcpu *pvm = ci->m.pvm;
    context_frame f = user_ctx->frame;
    f[FRAME_RIP] = pvm->rip;
    f[FRAME_RSP] = pvm->rsp;
    f[FRAME_EFLAGS] = pvm->eflags;
    f[FRAME_RCX] = pvm->rcx;
    f[FRAME_R11] = pvm->r11;
    syscall(user_ctx);
    pvm_frame_return(f);
}

void __attribute__((noreturn)) pvm_frame_return(context_frame f)
{
    if (f[FRAME_CS] & 0x3) {    /* (CPL != 0) means return to user mode */
        cpuinfo ci = current_cpu();
        context_frame f = get_current_context(ci)->frame;
        struct pvm_vcpu *pvm = ci->m.pvm;
        pvm->rip = f[FRAME_RIP];
        pvm->rsp = f[FRAME_RSP];
        pvm->eflags = f[FRAME_EFLAGS];
        pvm->rcx = f[FRAME_RCX];
        pvm->r11 = f[FRAME_R11];
    }
    pvm_event_return(f);
}
