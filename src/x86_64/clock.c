#include <runtime.h>
#include <x86_64.h>
#include "hpet.h"
#include "rtc.h"

static volatile struct pvclock_vcpu_time_info *vclock = 0;

static timestamp rtc_offset;

#define CPUID_LEAF_4 0x40000001

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
    u64 nsec =  ((u128)delta * vclock->tsc_to_system_mul) >> 32;
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

/* system timer that is reserved for processing the global timer heap */
void runloop_timer(timestamp duration)
{
    timer_function(duration);
}

void init_clock(kernel_heaps kh)
{
    heap backed = heap_backed(kh);
    // xxx - figure out how to deal with cpu id so we can
    // test for the presence of this feature
    // this is just used for rdtsc scaling, as both kvm and non-kvm are assumed
    // to have hpet support
    struct pvclock_vcpu_time_info * vc = allocate(backed, backed->pagesize);
    zero(vc, sizeof(struct pvclock_vcpu_time_info));
    vclock = vc;

    // add the enable bit 1
    write_msr(MSR_KVM_SYSTEM_TIME, physical_from_virtual(vc) | 1);
    memory_barrier();

    /* if we can't get pvclock, fall back on HPET */
    if (vclock->system_time == 0) {
        if (!init_hpet(heap_general(kh), heap_virtual_page(kh), heap_pages(kh))) {
            halt("HPET initialization failed; no timer source\n");
        }
        clock_function = now_hpet;
        timer_function = hpet_runloop_timer;
    } else {
        clock_function = now_kvm;
        timer_function = lapic_runloop_timer;
    }

    rtc_offset = rtc_gettimeofday() << 32;
}
