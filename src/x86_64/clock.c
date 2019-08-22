#include <runtime.h>
#include <x86_64.h>
#include <page.h>
#include "hpet.h"
#include "rtc.h"

#define CLOCK_INIT_DEBUG
#ifdef CLOCK_INIT_DEBUG
#define clock_init_debug(x) do {console(" CLK: " x "\n");} while(0)
#else
#define clock_init_debug(x)
#endif

static volatile struct pvclock_vcpu_time_info *vclock = 0;

static timestamp rtc_offset;

/* These should go in a KVM-specific area... */
#define KVM_CPUID_SIGNATURE 0x40000000
#define KVM_SIGNATURE_0 0x4b4d564b
#define KVM_SIGNATURE_1 0x564b4d56
#define KVM_SIGNATURE_2 0x0000004d
#define KVM_CPUID_FEATURES 0x40000001
#define MSR_KVM_SYSTEM_TIME 0x4b564d01

struct pvclock_vcpu_time_info {
    u32   version;
    u32   pad0;
    u64   tsc_timestamp;
    u64   system_time;
    u32   tsc_to_system_mul;
    s8    tsc_shift;
    u8    flags;
    u8    pad[2];
} __attribute__((__packed__));

#define MSR_KVM_WALL_CLOCK 0x4b564d00
struct pvclock_wall_clock {
    u32   version;
    u32   sec;
    u32   nsec;
} __attribute__((__packed__));

typedef __uint128_t u128;
typedef timestamp (*clock_now)(void);
typedef void (*clock_timer)(timestamp);

extern timestamp now_hpet();

timestamp now_kvm()
{
    u64 r = rdtsc();
    u64 delta = r - vclock->tsc_timestamp;
    if (vclock->tsc_shift < 0) {
        delta >>= -vclock->tsc_shift;
    } else {
        delta <<= vclock->tsc_shift;
    }
    // ok - a 64 bit number (?) multiplied by a 32 bit number yields
    // a 96 bit result, chuck the bottom 32 bits
    u64 nsec = vclock->system_time +
            (((u128)delta * vclock->tsc_to_system_mul) >> 32);
    u64 sec = nsec / BILLION;
    nsec -= sec * BILLION;
    timestamp out = seconds(sec) + nanoseconds(nsec);
    return out;
}

extern void lapic_runloop_timer(timestamp interval);

static clock_now clock_function = now_kvm;
static clock_timer timer_function = lapic_runloop_timer;

boolean using_lapic_timer(void)
{
    return timer_function == lapic_runloop_timer;
}

/* system time adjusted by rtc offset */
timestamp now() {
    return rtc_offset + clock_function();
}

timestamp uptime() {
    return clock_function();
}

void kern_sleep(timestamp delta)
{
    timestamp end = now() + delta;
    while (now() < end)
        asm volatile("pause");
}

/* system timer that is reserved for processing the global timer heap */
void runloop_timer(timestamp duration)
{
    timer_function(duration);
}

static boolean probe_kvm(void)
{
    clock_init_debug("probing for KVM...");
    u32 v[4];
    cpuid(KVM_CPUID_SIGNATURE, 0, v);
    if (!(v[1] == KVM_SIGNATURE_0 && v[2] == KVM_SIGNATURE_1 && v[3] == KVM_SIGNATURE_2)) {
        clock_init_debug("no KVM signature match");
        return false;
    }
    if (v[0] != KVM_CPUID_FEATURES) {
        console("KVM probe fail: found signature but unrecognized features cpuid ");
        print_u64(v[0]);
        console("; check KVM version?\n");
        return false;
    }
    return true;
}

static boolean probe_kvm_pvclock(kernel_heaps kh)
{
    if (!probe_kvm())
        return false;

    clock_init_debug("probing for KVM pvclock...");
    heap backed = heap_backed(kh);
    u32 v[4];
    cpuid(KVM_CPUID_FEATURES, 0, v);
    print_u64(v[0]);
    if ((v[0] & (1 << 3)) == 0) {
        clock_init_debug("no pvclock detected");
        return false;
    }
    clock_init_debug("pvclock detected");
    struct pvclock_vcpu_time_info * vc = allocate(backed, backed->pagesize);
    zero(vc, sizeof(struct pvclock_vcpu_time_info));
    clock_init_debug("before write msr");
    write_msr(MSR_KVM_SYSTEM_TIME, physical_from_virtual(vc) | /* enable */ 1);
    memory_barrier();
    clock_init_debug("after write msr");
    if (vc->system_time == 0) {
        /* noise, but we should know if this happens */
        console("kvm pvclock probe failed: detected kvm pvclock, but system_time == 0\n");
        return false;
    }
    vclock = vc;
    return true;
}

void init_clock(kernel_heaps kh)
{
    /* if we can't get pvclock, fall back on HPET */
    if (!probe_kvm_pvclock(kh)) {
        clock_init_debug("attempt init_hpet");
        if (!init_hpet(heap_general(kh), heap_virtual_page(kh), heap_pages(kh))) {
            halt("HPET initialization failed; no timer source\n");
        }
        clock_init_debug("HPET detected");
        clock_function = now_hpet;
        timer_function = hpet_runloop_timer;
    } else {
        clock_function = now_kvm;
        timer_function = lapic_runloop_timer;
    }

    rtc_offset = rtc_gettimeofday() << 32;
}
