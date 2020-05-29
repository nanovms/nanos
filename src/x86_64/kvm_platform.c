#include <kernel.h>
#include <page.h>
#include <pvclock.h>
#include <kvm_platform.h>
#include <apic.h>

//#define KVM_DEBUG
#ifdef KVM_DEBUG
#define kvm_debug(x) do {console(" KVM: " x "\n");} while(0)
#else
#define kvm_debug(x)
#endif

#define KVM_CPUID_SIGNATURE 0x40000000
#define KVM_SIGNATURE_0     0x4b4d564b
#define KVM_SIGNATURE_1     0x564b4d56
#define KVM_SIGNATURE_2     0x0000004d
#define KVM_CPUID_FEATURES  0x40000001
#define KVM_MSR_SYSTEM_TIME 0x4b564d01
#define KVM_MSR_WALL_CLOCK  0x4b564d00

void halt(char *format, ...)
{
    vlist a;
    buffer b = little_stack_buffer(512);
    struct buffer f;
    f.start = 0;
    f.contents = format;
    f.end = runtime_strlen(format);

    vstart(a, format);
    vbprintf(b, &f, &a);
    buffer_print(b);
    kernel_shutdown(VM_EXIT_HALT);
}

static boolean probe_kvm_pvclock(kernel_heaps kh)
{
    kvm_debug("probing for KVM pvclock...");
    heap backed = heap_backed(kh);
    u32 v[4];
    cpuid(KVM_CPUID_FEATURES, 0, v);
    if ((v[0] & (1 << 3)) == 0) {
        kvm_debug("no pvclock detected");
        return false;
    }
    kvm_debug("pvclock detected");
    struct pvclock_vcpu_time_info * vc = allocate(backed, backed->pagesize);
    zero(vc, sizeof(struct pvclock_vcpu_time_info));
    kvm_debug("before write msr");
    write_msr(KVM_MSR_SYSTEM_TIME, physical_from_virtual(vc) | /* enable */ 1);
    memory_barrier();
    kvm_debug("after write msr");
    if (vc->system_time == 0) {
        /* noise, but we should know if this happens */
        msg_err("kvm pvclock probe failed: detected kvm pvclock, but system_time == 0\n");
        return false;
    }
    init_pvclock(heap_general(kh), vc);
    return true;
}

boolean kvm_detect(kernel_heaps kh)
{
    kvm_debug("probing for KVM...");
    u32 v[4];
    cpuid(KVM_CPUID_SIGNATURE, 0, v);
    if (!(v[1] == KVM_SIGNATURE_0 && v[2] == KVM_SIGNATURE_1 && v[3] == KVM_SIGNATURE_2)) {
        kvm_debug("no KVM signature match");
        return false;
    }
    if (v[0] != KVM_CPUID_FEATURES) {
        msg_err("found signature but unrecognized features cpuid 0x%lx; check KVM version?", v[0]);
        return false;
    }
    if (!probe_kvm_pvclock(kh)) {
        msg_err("unable to probe pvclock\n");
        return false;
    }

    clock_timer ct;
    thunk per_cpu_init;
    if (init_tsc_deadline_timer(&ct, &per_cpu_init)) {
        kvm_debug("TSC Deadline available");
    } else if (init_lapic_timer(&ct, &per_cpu_init)) {
        kvm_debug("defaulting to (suboptimal) lapic timer");
    } else {
        halt("%s: no timer available\n", __func__);
    }

    register_platform_clock_timer(ct, per_cpu_init);
    return true;
}
