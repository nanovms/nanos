#include <runtime.h>
#include "hpet.h"

static struct pvclock_vcpu_time_info *vclock = 0;

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

typedef time (*clock_now)(void);

time now_kvm()
{
    u64 r = rdtsc();
    u64 nano = 1000000000ull;
    u64 delta = r - vclock->tsc_timestamp;
    if (vclock->tsc_shift < 0) {
        delta >>= -vclock->tsc_shift;
    } else {
        delta <<= vclock->tsc_shift;
    }
    // ok - a 64 bit number (?) multiplied by a 32 bit number yields
    // a 96 bit result, chuck the bottom 32 bits
    u64 nsec =  ((u128)delta * vclock->tsc_to_system_mul) >> 32;
    u64 sec = nsec / nano;
    nsec -= sec * nano;
    time out  = (sec<<32) + time_from_nsec(nsec);
    return out;
}

static clock_now clock_function = now_kvm;
extern time now_hpet();

time now() {
  return clock_function();
}

void configure_hpet_timer(int timer, time rate, thunk t);
void configure_lapic_timer(time rate, thunk t);

#if 0
void register_periodic_timer_interrupt(time interval, thunk handler)
{
    rprintf("register!\n");
    if (lapic){
        configure_lapic_timer(interval, handler);
    } else {
        if (hpet) {
            configure_hpet_timer(0, interval, handler);
        } else {
            halt("no timer hardware!");
        }
    }
}
#endif

void init_clock(kernel_heaps kh)
{
    heap backed = heap_backed(kh);
    // xxx - figure out how to deal with cpu id so we can
    // test for the presence of this feature
    vclock = allocate(backed, backed->pagesize);
    zero(vclock,sizeof(struct pvclock_vcpu_time_info));
    // add the enable bit 1
    write_msr(MSR_KVM_SYSTEM_TIME, physical_from_virtual(vclock)| 1);
    // xxx - there is a bit somewhere in the furthest leaves of the cpuid tree
    // that indicates kvm clock support
    // we aren't using this calibrator right now, but leave it for
    // rdtsc
    if(!init_hpet(kh->general, heap_virtual_page(kh), heap_pages(kh))) {
        halt("ERROR: HPET clock unvailable\n");
    }
    clock_function = now_hpet;
}
