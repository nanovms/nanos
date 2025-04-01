#include <kernel.h>
#include <pvclock.h>
#include <kvm_platform.h>
#include <apic.h>

//#define KVM_DEBUG
#ifdef KVM_DEBUG
#define kvm_debug(x) do {rputs(" KVM: " x "\n");} while(0)
#else
#define kvm_debug(x)
#endif

#define KVM_CPUID_BASE      0x40000000
#define KVM_CPUID_END       0x40000200

#define KVM_CPUID_SIGNATURE 0
#define KVM_SIGNATURE_0     0x4b4d564b
#define KVM_SIGNATURE_1     0x564b4d56
#define KVM_SIGNATURE_2     0x0000004d
#define KVM_CPUID_FEATURES  1
#define KVM_MSR_SYSTEM_TIME 0x4b564d01
#define KVM_MSR_WALL_CLOCK  0x4b564d00

static boolean probe_kvm_pvclock(kernel_heaps kh, u32 cpuid_fn)
{
    kvm_debug("probing for KVM pvclock...");
    heap backed = (heap)heap_linear_backed(kh);
    u32 v[4];
    cpuid(cpuid_fn + KVM_CPUID_FEATURES, 0, v);
    if ((v[0] & (1 << 3)) == 0) {
        kvm_debug("no pvclock detected");
        return false;
    }
    kvm_debug("pvclock detected");
    struct pvclock_vcpu_time_info * vc = mem_alloc(backed, backed->pagesize,
                                                   MEM_NOWAIT | MEM_NOFAIL);
    zero(vc, sizeof(struct pvclock_vcpu_time_info));
    kvm_debug("before write msr");
    physical vc_phys = physical_from_virtual(vc);
    write_msr(KVM_MSR_SYSTEM_TIME, vc_phys | /* enable */ 1);
    write_msr(KVM_MSR_WALL_CLOCK, vc_phys + sizeof(*vc));
    memory_barrier();
    kvm_debug("after write msr");
    if (vc->system_time == 0) {
        /* noise, but we should know if this happens */
        msg_err("kvm pvclock probe failed: detected kvm pvclock, but system_time == 0");
        return false;
    }
    init_pvclock(heap_general(kh), vc, (struct pvclock_wall_clock *)(vc + 1));
    return true;
}

boolean kvm_detect(kernel_heaps kh)
{
    kvm_debug("probing for KVM...");
    u32 fn;
    u32 v[4];
    for (fn = KVM_CPUID_BASE; fn < KVM_CPUID_END; fn += 0x100) {
        cpuid(fn + KVM_CPUID_SIGNATURE, 0, v);
        if (v[1] == KVM_SIGNATURE_0 && v[2] == KVM_SIGNATURE_1 && v[3] == KVM_SIGNATURE_2 &&
            v[0] >= fn + KVM_CPUID_FEATURES) {
            break;
        }
    }
    if (fn == KVM_CPUID_END)
        return false;
    if (!probe_kvm_pvclock(kh, fn)) {
        msg_err("kvm: unable to probe pvclock");
        return false;
    }

    clock_timer ct;
    thunk per_cpu_init;
    if (init_tsc_deadline_timer(&ct, &per_cpu_init)) {
        kvm_debug("TSC Deadline available");
    } else if (init_lapic_timer(&ct, &per_cpu_init)) {
        kvm_debug("defaulting to (suboptimal) lapic timer");
    } else {
        halt("%s: no timer available\n", func_ss);
    }

    register_platform_clock_timer(ct, per_cpu_init);
    return true;
}
